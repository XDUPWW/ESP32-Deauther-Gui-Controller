"""Soak test: run every new module for N minutes and prove the radio never refuses a frame.

    python lab/soak.py --port COM5 --bssid BE:41:99:0B:20:36 --minutes 5

For each module the script scans, starts the module, lets it run, then reads STATUS while it
is still running and reports the counters that matter:

    txgok   frames the tx_guard handed to the driver and the driver accepted
    txgerr  frames the driver refused  <-- must stay 0, this is the 0x101 counter
    txg     frames the governor held back (expected: it is the pacing itself)

A `FATAL tx 0x101` line anywhere in the run fails the whole soak. The board is never reset
by the script (that would hide a restart), so a restart shows up as a `FATAL`/boot banner in
the stream and as a scan index of -1 afterwards.
"""
import argparse
import re
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import serial

FATAL = re.compile(r"FATAL tx 0x101")


def read_status(ser, timeout=6.0):
    ser.reset_input_buffer()
    ser.write(b"STATUS\r\n")
    ser.flush()
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = ser.readline().decode("utf-8", "replace").rstrip()
        if line.startswith("STATUS "):
            fields = {}
            for token in line.split(" ")[1:]:
                if "=" in token:
                    key, _, value = token.partition("=")
                    fields[key] = value
            return fields
    return {}


def scan_for(ser, bssid, attempts=4, timeout=25.0):
    for _ in range(attempts):
        ser.reset_input_buffer()
        ser.write(b"SCAN\r\n")
        ser.flush()
        idx = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = ser.readline().decode("utf-8", "replace").rstrip()
            if line.startswith("NET "):
                parts = line.split(" ", 6)
                if len(parts) >= 6 and parts[5].upper() == bssid:
                    idx = int(parts[1])
            elif line.startswith("SCAN_END"):
                break
        if idx is not None:
            return idx
        time.sleep(1.0)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--bssid", required=True)
    ap.add_argument("--minutes", type=float, default=5.0)
    ap.add_argument("--only", default=None)
    args = ap.parse_args()
    target = args.bssid.upper()
    seconds = args.minutes * 60.0

    ser = serial.Serial(args.port, 115200, timeout=0.2)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.5)
    ser.reset_input_buffer()
    time.sleep(0.5)
    ser.write(b"PING\r\n")
    ser.flush()

    fake = "02AABBCCDDEE"
    plan = [
        ("sae", "SAE {idx} point 50", "SAESTOP", "saef"),
        ("authflood", "AUTHFLOOD {idx} both noauto", "AUTHFLOODSTOP", "aff"),
        ("tim", "TIM {idx} tim 0", "TIMSTOP", "timf"),
        ("eapol", "EAPOL {idx} 6 " + fake, "EAPOLSTOP", "eapf"),
        ("wnm", "WNM {idx} cand 10 6 " + fake, "WNMSTOP", "wnmf"),
    ]
    failures = 0
    print("%-10s %8s %8s %8s %8s  %s" % ("module", "frames", "guard+", "txg", "txgerr", "result"))
    prev_txgok = 0
    for name, start_fmt, stop_cmd, counter in plan:
        if args.only and args.only != name:
            continue
        idx = scan_for(ser, target)
        if idx is None:
            print("%-10s target not found in the scan" % name)
            failures += 1
            continue
        start_cmd = start_fmt.format(idx=idx)
        ser.write((start_cmd + "\r\n").encode())
        ser.flush()
        started = time.time()
        ok_line = None
        fatals = 0
        while time.time() - started < 3.0:
            line = ser.readline().decode("utf-8", "replace").rstrip()
            if line.startswith("OK "):
                ok_line = line
                break
            if line.startswith("ERR "):
                ok_line = line
                break
        if not ok_line or ok_line.startswith("ERR"):
            print("%-10s start failed: %r" % (name, ok_line))
            failures += 1
            continue

        # Soak: keep reading (so a FATAL is not missed) until the window is over.
        deadline = time.time() + seconds
        while time.time() < deadline:
            line = ser.readline().decode("utf-8", "replace").rstrip()
            if FATAL.search(line):
                fatals += 1
                print("%-10s FATAL during soak: %s" % (name, line))
                break
        status = read_status(ser)
        frames = status.get(counter, "0")
        try:
            sent = int(status.get("txgok", "0")) - prev_txgok
            prev_txgok = int(status.get("txgok", "0"))
        except ValueError:
            sent = -1
        row = (name, frames, str(sent), status.get("txg", "-"), status.get("txgerr", "-"))
        bad = bool(fatals) or status.get("txgerr") not in ("0", None) or frames in ("0", "", None)
        # Cross-check: the guard counts every frame it accepted, the module counts its own.
        # A large gap means one of the two counters (or the STATUS read) is wrong.
        drift = ""
        try:
            mine, guard = int(frames), sent
            if guard > 0 and abs(mine - guard) > max(20, guard // 5):
                drift = "  [counter drift: module=%d guard=%d]" % (mine, guard)
        except ValueError:
            pass
        print("%-10s %8s %8s %8s %8s  %s%s" % (row + ("FAIL" if bad else "ok", drift)))
        if bad:
            failures += 1
        ser.write((stop_cmd + "\r\n").encode())
        ser.flush()
        time.sleep(1.0)

    final = read_status(ser)
    print("\nfinal STATUS: txgok=%s txg=%s txgerr=%s heap=%s networks=%s"
          % (final.get("txgok"), final.get("txg"), final.get("txgerr"),
             final.get("heap"), final.get("networks")))
    ser.close()
    print("RESULT:", "all modules stable" if failures == 0 else "%d failure(s)" % failures)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
