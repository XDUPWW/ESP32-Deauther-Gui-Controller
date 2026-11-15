"""Verify the TIM clone's on-air bitmap without the C5 capture pipe.

    python lab/tim_air.py --attack COM5 --sniff COM6 --channel 12 --aid 3

Why this exists: the C5 capture stack (named pipe + `cap_frames.py`) is the primary
way to read frames off the air, but it is a separate project and is not always
running. The lab firmware has a `sniff <ch>` command that prints the TIM element of
every beacon it hears, which is enough to answer the only question here: *does the
byte we build reach the air unchanged, with the victim's AID in the right bit?*

Topology:

  COM6  ESP32       lab/rf_throughput `sniff <ch>`  -> `BEACON ta=.. seq=.. tim=..`
  COM5  ESP32-CYD   this firmware `TIM <idx> tim <aid>`

Expected clone line: `ta=<AP BSSID> seq=1515` (the clone's sequence control is the
fixed 0xF0FF) and `tim=00<dtim_period>0008` for AID 3 -- body layout is
`dtim_count(1) dtim_period(1) bitmap_control(1) partial_virtual_bitmap(..)`, and
AID n lives in bit n%8 of byte n/8, so AID 3 is 0x08 in the first bitmap byte.
"""
import argparse
import collections
import re
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import serial


class Port:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.05)
        self.ser.dtr = False
        self.ser.rts = False
        time.sleep(0.3)
        self.ser.reset_input_buffer()

    def send(self, line):
        self.ser.write((line + "\r\n").encode())
        self.ser.flush()

    def read_line(self, timeout=0.05):
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
        self.ser.close()


LINE = re.compile(r"^BEACON ta=([0-9A-F:]{17}) seq=(\d+) interval=(\d+) tim=([0-9A-F]*)$")


def decode_tim(body):
    raw = bytes.fromhex(body)
    if len(raw) < 4:
        return None
    dtim_count, dtim_period, ctrl = raw[0], raw[1], raw[2]
    bitmap = raw[3:]
    aids = []
    for index, byte in enumerate(bitmap):
        for bit in range(8):
            if byte & (1 << bit):
                aids.append(8 * index + bit)
    return {
        "dtim_count": dtim_count,
        "dtim_period": dtim_period,
        "group": bool(ctrl & 0x01),
        "offset": ctrl >> 1,
        "bitmap": bitmap.hex().upper(),
        "aids": aids,
    }


def scan_for(attack, bssid, tries=3):
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
                if len(parts) >= 6 and parts[5].upper() == bssid:
                    index = int(parts[1])
            if text.startswith("SCAN_END"):
                break
        if index is not None:
            return index
        time.sleep(1.0)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="COM5")
    ap.add_argument("--sniff", default="COM6")
    ap.add_argument("--bssid", required=True, help="target AP BSSID (upper case)")
    ap.add_argument("--channel", type=int, default=12)
    ap.add_argument("--aid", type=int, default=3)
    ap.add_argument("--seconds", type=float, default=6.0)
    ap.add_argument("--mode", default="tim", choices=("tim", "clear"))
    args = ap.parse_args()
    target = args.bssid.upper()

    sniffer = Port(args.sniff)
    attack = Port(args.attack)
    try:
        sniffer.send("sniff %d" % args.channel)
        print("sniff:", sniffer.expect(("OK sniff", "ERR "), 8.0) or "no answer")

        index = scan_for(attack, target)
        if index is None:
            print("target %s not in the attack board's scan" % target)
            return 1
        print("attack index=%d" % index)

        attack.send("TIM %d %s %d" % (index, args.mode, args.aid))
        print("attack:", attack.expect(("OK TIM ", "ERR "), 6.0) or "no answer")

        seen = collections.Counter()
        groups = {}
        clone = []
        deadline = time.time() + args.seconds
        while time.time() < deadline:
            text = sniffer.read_line(0.1)
            if text is None or not text.startswith("BEACON "):
                continue
            match = LINE.match(text)
            if not match:
                continue
            ta, seq, interval, body = match.groups()
            seen[(ta, body)] += 1
            groups.setdefault((ta, body), decode_tim(body))

        attack.send("TIMSTOP")
        sniffer.send("sniffstop")
        print("sniffer:", sniffer.expect("OK sniff end", 5.0) or "")

        print("\nbeacons seen (TA, TIM body) -> count / decoded:")
        for (ta, body), count in seen.most_common(12):
            decoded = groups[(ta, body)]
            if decoded is None:
                print("  %s %-14s x%-3d (too short)" % (ta, body, count))
                continue
            print("  %s %-14s x%-3d dtim=%d/%d group=%d offset=%d bitmap=%s aids=%s"
                  % (ta, body, count, decoded["dtim_count"], decoded["dtim_period"],
                     decoded["group"], decoded["offset"], decoded["bitmap"],
                     decoded["aids"]))

        want_aid = args.aid
        hits = 0
        for (ta, body), count in seen.items():
            if ta != target:
                continue
            decoded = groups[(ta, body)]
            if decoded is None:
                continue
            if args.mode == "clear":
                if decoded["bitmap"].strip("0") == "" and not decoded["group"]:
                    hits += count
            elif want_aid in decoded["aids"]:
                hits += count
        total = sum(seen.values())
        print("\nRESULT: %d/%d beacons on %s carry %s"
              % (hits, total, target,
                 ("an empty bitmap (clear mode)" if args.mode == "clear"
                  else "AID %d in the partial virtual bitmap" % want_aid)))
        return 0 if hits > 0 else 1
    finally:
        for port in (sniffer, attack):
            try:
                port.close()
            except Exception:  # noqa: BLE001
                pass


if __name__ == "__main__":
    sys.exit(main())
