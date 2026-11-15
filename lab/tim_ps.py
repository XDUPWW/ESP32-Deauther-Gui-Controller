"""TIM poisoning against a real power-saving station (three boards).

    python lab/tim_ps.py --attack COM5 --ap COM6 --sta COM10 --channel 6

Topology (all boards on one desk, one channel):

  COM6   ESP32     lab/rf_throughput `ap <ssid> <ch>`   -> softAP + TCP 4444 stream
  COM10  ESP32-C5  lab/rf_throughput `sta <ssid>` + `ps 1` -> downloads, DTIM wakeups
  COM5   ESP32-CYD this firmware -> TIM attack against that softAP

Why a power-saving station is the point: a station that never sleeps ignores the TIM
element, so the only way to see the attack is to put the victim into
WIFI_PS_MIN_MODEM (wake per DTIM) and watch what the download does.

Throughput is read from **the AP's** RATE lines, not the station's: a C5 in modem sleep
stalls its own USB-CDC output (the print blocks until the next wake), which made the
first version of this script report 2 samples instead of 10. The station's lines are
still printed when they arrive, because a disconnect there is a result too.

Phases, `--seconds` each, back to back on one link:

  baseline ps   no attack, station asleep (ps 1)   -> the link's own rate
  clear         `TIM <idx> clear`                  -> clone claims "nobody has buffered
                                                      data"; the sleeping station should
                                                      miss downlink
  tim           `TIM <idx> tim 0`                  -> clone claims "you have buffered
                                                      data"; the station wakes/polls for
                                                      nothing: costs power, not throughput
  baseline awake `ps 0`, no attack                 -> the same link with power save off,
                                                      i.e. how much of the drop is just PS

Every board is `clear`+`reboot`ed first: a role left in NVS from an earlier run would
otherwise auto-start and fight the one this script wants.
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


def status_of(attack):
    attack.send("STATUS")
    line = attack.expect("STATUS ", 5.0)
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
        if printed and printed.startswith("ERR"):
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
        attack.expect("OK ", 5.0)
    return {"ap": ap_rates, "sta": sta_rates, "disconnects": disconnects}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="COM5")
    ap.add_argument("--ap", default="COM6")
    ap.add_argument("--sta", default="COM10")
    ap.add_argument("--ssid", default="timlab")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--seconds", type=float, default=12.0)
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
        board_sta.send("ps 1")
        print("sta:", board_sta.expect("OK ps=1", 5.0) or "ps not applied")
        print("sta:", board_sta.expect("WIFI sta got ip", 25.0) or "no ip")
        print("sta:", board_sta.expect("STA connected", 25.0) or "no TCP stream")

        index = scan_for(attack, args.ssid)
        if index is None:
            print("attack board did not see the softAP '%s'" % args.ssid)
            return 1
        print("attack index=%d" % index)

        ports = {"ap": board_ap, "sta": board_sta}
        results = {}
        results["baseline ps"] = phase("baseline ps (no attack)", attack, args.seconds, ports)
        results["clear"] = phase("TIM clear", attack, args.seconds, ports,
                                 "TIM %d clear" % index, "TIMSTOP")
        results["tim"] = phase("TIM tim", attack, args.seconds, ports,
                              "TIM %d tim 0" % index, "TIMSTOP")
        board_sta.send("ps 0")
        board_sta.expect("OK ps=0", 5.0)
        results["baseline awake"] = phase("baseline awake (ps 0, no attack)", attack,
                                         args.seconds, ports)

        info = status_of(attack)
        print("\nSTATUS tim=%s timf=%s timreal=%s timaid=%s txg=%s txgerr=%s"
              % (info.get("tim"), info.get("timf"), info.get("timreal"),
                 info.get("timaid"), info.get("txg"), info.get("txgerr")))

        base = results["baseline ps"]["ap"]
        base = statistics.mean(base) if base else float("nan")
        print("\nsummary (AP-side RATE KiB/s, 'baseline ps'=%.0f):" % base)
        for name in ("baseline ps", "clear", "tim", "baseline awake"):
            res = results.get(name)
            if not res or not res["ap"]:
                continue
            mean = statistics.mean(res["ap"])
            delta = (mean - base) / base * 100 if base else float("nan")
            print("  %-15s mean=%7.0f  (%+6.1f%%)  n=%2d  sta_disconnects=%d"
                  % (name, mean, delta, len(res["ap"]), res["disconnects"]))
        return 0
    finally:
        for port in (board_ap, board_sta, attack):
            port.close()


if __name__ == "__main__":
    sys.exit(main())
