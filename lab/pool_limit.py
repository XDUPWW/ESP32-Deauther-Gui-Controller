"""How many frames does each module get before the driver answers 0x101?

    python lab/pool_limit.py --port COM5 --bssid BE:41:99:0B:20:36 --module tim

Each module is started on its own and the serial line is read until the tx guard prints
its FATAL line (which carries the number of frames that went through). The board
restarts itself at that point -- that is the firmware rule, not a failure -- so every
run re-scans before starting.
"""
import argparse
import re
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import serial

FATAL = re.compile(r"FATAL tx 0x101 .*ok=(\d+) err=(\d+)")


def scan_and_find(ser, bssid, wait=25.0):
    ser.reset_input_buffer()
    ser.write(b"SCAN\r\n")
    ser.flush()
    index, channel = None, None
    deadline = time.time() + wait
    while time.time() < deadline:
        line = ser.readline().decode("utf-8", "replace").rstrip("\r\n")
        if line.startswith("NET "):
            parts = line.split(" ", 6)
            if len(parts) >= 6 and parts[5].upper() == bssid:
                index, channel = int(parts[1]), int(parts[3])
        elif line.startswith("SCAN_END"):
            break
    return index, channel


def run(ser, command, timeout):
    ser.write((command + "\r\n").encode())
    ser.flush()
    started = time.time()
    deadline = started + timeout
    ok = err = None
    echo = []
    while time.time() < deadline:
        line = ser.readline().decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            continue
        if line.startswith("FATAL"):
            match = FATAL.search(line)
            if match:
                ok, err = int(match.group(1)), int(match.group(2))
            echo.append(line)
            break
        if line.startswith("OK ") or line.startswith("ERR "):
            echo.append(line)
    return ok, err, time.time() - started, echo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM5")
    ap.add_argument("--bssid", required=True)
    ap.add_argument("--module", default="tim",
                    choices=("tim", "sae", "eapol", "authflood", "wnm"))
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--gap", type=int, default=20, help="SAE gap_ms (frame spacing)")
    args = ap.parse_args()

    ser = serial.Serial(args.port, 115200, timeout=0.2)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.5)
    ser.reset_input_buffer()
    time.sleep(0.5)

    index, channel = scan_and_find(ser, args.bssid.upper())
    if index is None:
        print("target not found")
        return 1
    print("target index=%d channel=%d" % (index, channel))

    fake = "02AABBCCDDEE"
    commands = {
        "tim": "TIM %d tim 0" % index,
        "sae": "SAE %d point %d" % (index, args.gap),
        "eapol": "EAPOL %d 6 %s" % (index, fake),
        "authflood": "AUTHFLOOD %d both noauto" % index,
        "btm": "BTM %d 10 %s" % (index, fake),
    }
    cmd = commands[args.module]
    print("start: %s" % cmd)
    ok, err, seconds, echo = run(ser, cmd, args.timeout)
    for line in echo[:2]:
        print("  %s" % line)
    if ok is None:
        print("no 0x101 within %.0f s (module still running)" % seconds)
        ser.write(b"STOP\r\n")
        ser.flush()
    else:
        print("0x101 after %d frames (%.1f s) -> %.1f frames/s" % (ok, seconds, ok / seconds))
    ser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
