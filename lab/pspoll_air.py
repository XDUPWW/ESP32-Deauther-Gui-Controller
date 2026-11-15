"""Air check for the PM-bit spoof: which frame shape actually leaves the radio.

    python -u lab/pspoll_air.py --attack COM5 --sniff COM6 --channel 6

The attack has three interchangeable carriers for the same Power Management bit, and
stacks disagree about which one they honour, so all three are verified separately:

  * `null`    Null Data    data subtype 4 , Frame Control byte1 bit4 = PM
  * `qosnull` QoS Null     data subtype 12, same bit + 2-byte QoS Control
  * `action`  Action       mgmt subtype 13, same bit, category 127 (vendor specific)

Each frame is sent with PM=1, every sixth one with PM=0.

Topology -- one wire only, because the sniffer has to own the channel:

  COM6   ESP32     lab/rf_throughput `ap pspollab 6` + `sniffpoll 6`
                   softAP for the attack board to aim at, *and* the sniffer. A
                   dedicated sniffer (bare STA interface) captured almost nothing in
                   the runs of 2026-11-15; with a running AP on the same radio it
                   captured 7-10 of every 10 injected frames.
  COM5   ESP32-CYD this firmware, `PSPOLL <idx> 02AABBCCDDEE <shape>`

One trap this script works around: a channel change is refused while the station is
still finishing a SCAN, and the module would then transmit on whatever channel the
scan stopped on. The attack board is therefore parked with `MON <ch> 2` first, and
the module's own `chset=` verdict is printed.

Verdict: the shape reached the air if its frames were captured with `pm=1`.
"""
import argparse
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import serial

SHAPES = ("null", "qosnull", "action")


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
    """Erase the stored role and reboot, so the board comes up idle."""
    p = Port(port)
    p.send("clear")
    p.expect("OK cleared", 3.0)
    p.send("reboot")
    p.expect("OK rebooting", 3.0)
    p.close()
    time.sleep(0.8)
    p = Port(port)
    p.expect("INFO lab rf_throughput ready", 15.0)
    return p


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


def parse_fields(line):
    fields = {}
    for token in line.split(" ")[1:]:
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value
    return fields


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="COM5")
    ap.add_argument("--sniff", default="COM6")
    ap.add_argument("--ssid", default="pspollab")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--victim", default="02AABBCCDDEE")
    ap.add_argument("--seconds", type=float, default=4.0)
    args = ap.parse_args()

    board_sniff = reset_board(args.sniff)
    attack = Port(args.attack)
    results = {}
    try:
        board_sniff.send("ap %s %d" % (args.ssid, args.channel))
        print("ap:", board_sniff.expect("AP listening", 15.0) or "no answer")

        attack.send("STOP")
        attack.expect("OK STOP", 5.0)
        index = scan_for(attack, args.ssid)
        if index is None:
            print("attack board did not see the softAP '%s'" % args.ssid)
            return 1
        print("attack index=%d" % index)

        # Park the channel: a channel change requested while the station is still
        # finishing the scan is refused, and the frames would leave on the wrong one.
        attack.send("MON %d 2" % args.channel)
        time.sleep(2.5)

        for shape in SHAPES:
            attack.send("PSPOLL %d %s %s" % (index, args.victim, shape))
            started = attack.expect(("OK PSPOLL ", "ERR "), 6.0)
            print("\n--- %s\n    %s" % (shape, started))
            if started is None or started.startswith("ERR"):
                results[shape] = None
                continue
            chan_warn = attack.expect("WARN ", 1.0)
            if chan_warn:
                print("    ", chan_warn)

            board_sniff.send("sniffpoll %d" % args.channel)
            board_sniff.expect(("OK sniffpoll", "NOTE ", "ERR "), 6.0)
            nulls = {"0": 0, "1": 0}
            actions = {"0": 0, "1": 0}
            sample = []
            deadline = time.time() + args.seconds
            while time.time() < deadline:
                text = board_sniff.read_line(0.05)
                if text is None:
                    continue
                if text.startswith("NULL "):
                    row = parse_fields(text)
                    nulls[row.get("pm", "?")] = nulls.get(row.get("pm", "?"), 0) + 1
                    if len(sample) < 2:
                        sample.append(text)
                elif text.startswith("PMACT "):
                    row = parse_fields(text)
                    actions[row.get("pm", "?")] = actions.get(row.get("pm", "?"), 0) + 1
                    if len(sample) < 2:
                        sample.append(text)
            attack.send("PSPOLLSTOP")
            stop_line = attack.expect(("OK PSPOLLSTOP", "ERR "), 6.0)
            board_sniff.send("sniffstop")
            board_sniff.expect("OK sniff end", 8.0)
            results[shape] = (nulls, actions, sample, stop_line)
            print("    null-data frames: %s   action frames: %s" % (nulls, actions))
            print("    stop: %s" % stop_line)
            for line in sample:
                print("    e.g. %s" % line)

        print("\nverdict (frames that carried PM=1 on the air):")
        ok = True
        for shape in SHAPES:
            res = results.get(shape)
            if res is None:
                print("  %-8s did not start" % shape)
                ok = False
                continue
            nulls, actions, _sample, _stop = res
            pm1 = (nulls.get("1", 0) if shape != "action" else 0) + actions.get("1", 0)
            print("  %-8s pm=1 frames captured: %-3d  %s"
                  % (shape, pm1, "YES" if pm1 else "NO"))
            if not pm1:
                ok = False
        return 0 if ok else 2
    finally:
        for port in (board_sniff, attack):
            port.close()


if __name__ == "__main__":
    sys.exit(main())
