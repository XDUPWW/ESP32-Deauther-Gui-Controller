"""Air check for the PS-Poll / PM-bit spoof (three boards, no capture pipe).

    python -u lab/pspoll_air.py --attack COM5 --sniff COM6 --channel 6

Why this exists: the two fields that make the attack work live in the 802.11 header
and nowhere else --

  * PS-Poll (control subtype 10) Duration/ID = 0xC000 | AID, i.e. the AID of the
    station the forged poll claims to be;
  * Null Data (data subtype 4) Frame Control byte 1 bit 4 = the Power Management
    bit, i.e. "I am asleep, buffer my downlink".

Both are written by us and could be rewritten by the MAC (measured on RTS: 990..1102
us instead of the 12001 us an earlier module wrote; on management frames: 314 us),
so neither can be assumed to survive. This script makes the attack board send both
frames with a distinctive AID (37) and a known victim MAC, while a second board
sniffs the channel and prints what actually went out.

Topology -- one wire only, because the sniffer has to own the channel:

  COM6   ESP32     lab/rf_throughput `ap pspollab 6` + `sniffpoll 6`
                   softAP for the attack board to aim at, *and* the sniffer. A
                   dedicated sniffer (bare STA interface) captured almost nothing
                   in the runs of 2026-11-15; with a running AP on the same radio it
                   captured 7-10 of every 10 injected frames.
  COM5   ESP32-CYD this firmware, `PSPOLL <idx> 37 02AABBCCDDEE both`

One trap this script works around: a channel change is refused while the station is
still finishing a SCAN, and the module would then transmit on whatever channel the
scan stopped on. The attack board is therefore parked with `MON <ch> 2` first, and
the module's own `chset=` verdict is printed.

Verdict: `aid=37` and `pm=1` on the air = the header fields survive. Anything else
means the MAC rewrote them and the affected half of the attack cannot be aimed.
"""
import argparse
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
    ap.add_argument("--aid", type=int, default=37)
    ap.add_argument("--victim", default="02AABBCCDDEE")
    ap.add_argument("--seconds", type=float, default=6.0)
    args = ap.parse_args()

    board_sniff = reset_board(args.sniff)
    attack = Port(args.attack)
    polls = []
    nulls = []
    try:
        board_sniff.send("ap %s %d" % (args.ssid, args.channel))
        print("ap:", board_sniff.expect("AP listening", 15.0) or "no answer")

        index = scan_for(attack, args.ssid)
        if index is None:
            print("attack board did not see the softAP '%s'" % args.ssid)
            return 1
        print("attack index=%d" % index)

        # Park the channel: a channel change requested while the station is still
        # finishing the scan is refused, and the frames would leave on the wrong one.
        attack.send("MON %d 2" % args.channel)
        time.sleep(2.5)

        attack.send("PSPOLL %d %d %s both" % (index, args.aid, args.victim))
        print("start:", attack.expect(("OK PSPOLL ", "ERR "), 6.0))
        chan_warn = attack.expect("WARN ", 1.0)
        if chan_warn:
            print("warn: ", chan_warn)

        board_sniff.send("sniffpoll %d" % args.channel)
        print("sniff:", board_sniff.expect(("OK sniffpoll", "NOTE ", "ERR "), 6.0))

        deadline = time.time() + args.seconds
        while time.time() < deadline:
            text = board_sniff.read_line(0.05)
            if text is None:
                continue
            if text.startswith("POLL "):
                polls.append(parse_fields(text))
            elif text.startswith("NULL "):
                nulls.append(parse_fields(text))

        attack.send("PSPOLLSTOP")
        print("stop: ", attack.expect(("OK PSPOLLSTOP", "ERR "), 6.0))
        attack.send("STATUS")
        status = attack.expect("STATUS ", 5.0)
        board_sniff.send("sniffstop")
        end_line = board_sniff.expect("OK sniff end", 8.0)
        print("sniff:", end_line)

        print("\n--- what went out (%.1f s)" % args.seconds)
        aids = {}
        durs = {}
        tas = {}
        for row in polls:
            aids[row.get("aid")] = aids.get(row.get("aid"), 0) + 1
            durs[row.get("dur")] = durs.get(row.get("dur"), 0) + 1
            ta = row.get("ta", "?")
            tas[ta] = tas.get(ta, 0) + 1
        pms = {}
        for row in nulls:
            pms[row.get("pm")] = pms.get(row.get("pm"), 0) + 1
        print("  PS-Poll  frames=%d  aid histogram=%s  dur histogram=%s"
              % (len(polls), aids, dict(list(durs.items())[:6])))
        print("  PS-Poll  ta histogram=%s" % dict(list(tas.items())[:6]))
        print("  Null Data frames=%d  pm histogram=%s" % (len(nulls), pms))
        ctrl = {}
        if end_line and "ctrl=" in end_line:
            for subtype, value in enumerate(end_line.split("ctrl=")[1].split(",")):
                try:
                    if int(value) > 0:
                        ctrl[subtype] = int(value)
                except ValueError:
                    pass
        print("  control frames heard by subtype: %s" % (ctrl or "none"))
        if status:
            keys = ("psp", "pspf", "pspnul", "psppol", "pspfl", "pspc", "pspdl", "pspaid")
            print("  attack STATUS: " +
                  " ".join("%s=%s" % (k, status.split("%s=" % k)[1].split()[0])
                           if (" %s=" % k) in status else "%s=?" % k for k in keys))

        want_aid = str(args.aid)
        ok_aid = want_aid in aids
        ok_pm = pms.get("1", 0) > 0
        print("\nverdict:")
        print("  AID %s on the air: %s" % (want_aid, "YES" if ok_aid else "NO"))
        print("  PM=1 on the air:    %s" % ("YES" if ok_pm else "NO"))
        if not ok_aid:
            print("  -> Duration/ID did not survive as an AID. See 测试报告 §4.4.9.")
        if not ok_pm:
            print("  -> the PM bit did not survive: the Null Data half cannot set it.")
        return 0 if (ok_aid and ok_pm) else 2
    finally:
        for port in (board_sniff, attack):
            port.close()


if __name__ == "__main__":
    sys.exit(main())
