"""End-to-end air check: drive the attack board and capture the result on the C5 pipe.

    python lab/air_check.py --port COM5 --bssid BE:41:99:0B:20:36

The board is scanned once, the index of --bssid is looked up from the NET lines, and
then one attack at a time is started, captured for --seconds, decoded and stopped, so
every module gets its own evidence with nothing else on the air. The serial port stays
open the whole time (opening or closing it can reset the board and kill the attack).
"""
import argparse
import sys
import threading
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import serial

import cap_frames
import cap_pipe


class Board:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.1)
        self.ser.dtr = False
        self.ser.rts = False
        time.sleep(0.3)
        self.ser.reset_input_buffer()

    def send(self, line, wait=2.0, until=None):
        self.ser.write((line + "\r\n").encode())
        self.ser.flush()
        out = []
        deadline = time.time() + wait
        while time.time() < deadline:
            text = self.ser.readline().decode("utf-8", "replace").rstrip("\r\n")
            if not text:
                continue
            out.append(text)
            if text.startswith("ERR "):
                break
            if until and text.startswith(until):
                break
            if text.startswith("OK "):
                break
        return out

    def close(self):
        self.ser.close()


def capture(seconds, save=None):
    result = {}
    t = threading.Thread(target=cap_pipe.read_pipe, args=("esp_sdr_wifi", seconds, result))
    t.start()
    t.join()
    if "error" in result:
        print("pipe error: %s" % result["error"])
        return None
    blob = result.get("data", b"")
    if save:
        with open(save, "wb") as f:
            f.write(blob)
    return blob


def report(title, blob, bssid):
    print("\n=== %s ===" % title)
    if not blob:
        print("no capture")
        return
    import collections
    out = collections.defaultdict(int)
    for key in ("btm_samples", "btm_resp_samples", "sae_samples", "auth_samples",
                "token_samples", "beacon_samples", "eapol_samples"):
        out[key] = []
    total = 0
    for _ts, pkt, linktype in cap_pipe.parse_pcap(blob):
        if linktype == 127:
            pkt = cap_pipe.skip_radiotap(pkt)
        total += 1
        cap_frames.decode(pkt, bssid, out)
    print("frames=%d forged-TA=%d  BTM=%d SAE=%d AUTH=%d EAPOL=%d(status76=%d) forged_beacons=%d"
          % (total, out["forged_ta"], out["btm"], out["sae"], out["auth"], out["eapol"],
             out["sae_token_resp"], out["beacon_forged_seq"]))
    for key, label in (("btm_samples", "btm"), ("btm_resp_samples", "btm-response"),
                       ("sae_samples", "sae"), ("auth_samples", "auth"),
                       ("token_samples", "anti-clogging"), ("eapol_samples", "eapol"),
                       ("beacon_samples", "beacon")):
        for s in out[key]:
            print("  %-14s %s" % (label, s))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--bssid", required=True)
    ap.add_argument("--seconds", type=float, default=4.0)
    ap.add_argument("--only", default=None, help="run one test: btm|qosnull|eapol|sae|authflood")
    args = ap.parse_args()
    target = args.bssid.upper()

    board = Board(args.port)
    print("board:", board.send("PING"))

    index, channel = None, None
    for attempt in range(3):
        board.ser.reset_input_buffer()
        board.ser.write(b"SCAN\r\n")
        board.ser.flush()
        deadline = time.time() + 25
        while time.time() < deadline:
            text = board.ser.readline().decode("utf-8", "replace").rstrip("\r\n")
            if text.startswith("NET "):
                # NET <idx> <rssi> <ch> <enc> <bssid> <ssid...>
                parts = text.split(" ", 6)
                if len(parts) >= 6 and parts[5].upper() == target:
                    index = int(parts[1])
                    channel = int(parts[3])
            if text.startswith("SCAN_END"):
                print("scan %d -> %s" % (attempt + 1, text))
                break
        if index is not None:
            break
        time.sleep(1.0)
    if index is None:
        print("target %s not found in the scan" % target)
        board.close()
        return 1
    print("target index=%d channel=%d" % (index, channel))
    fake_sta = "02AABBCCDDEE"

    tests = [
        ("btm", "BTM %d 10 %s" % (index, fake_sta), "BTMSTOP"),
        ("qosnull", "QOSNULL %d %s" % (index, fake_sta), "QOSNULLSTOP"),
        ("eapol", "EAPOL %d 6 %s" % (index, fake_sta), "EAPOLSTOP"),
        ("sae", "SAE %d point 20" % index, "SAESTOP"),
        ("authflood", "AUTHFLOOD %d both noauto" % index, "AUTHFLOODSTOP"),
    ]
    for name, start_cmd, stop_cmd in tests:
        if args.only and args.only != name:
            continue
        print("\n--- start: %s" % start_cmd)
        for line in board.send(start_cmd, wait=4.0):
            print("    " + line)
        time.sleep(0.5)
        blob = capture(args.seconds, save=None)
        report(name, blob, target)
        for line in board.send(stop_cmd, wait=3.0):
            print("    " + line)
    for line in board.send("STATUS", wait=3.0):
        print(line)
    board.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
