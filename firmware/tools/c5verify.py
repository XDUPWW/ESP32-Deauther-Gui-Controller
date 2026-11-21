"""Check what the C5's own monitor callback reports for frames we inject.

The injector is whatever board runs firmware-v2 (radio.tx_test / radio.tx_bench),
the listener is the C5 running the classic firmware with the extended RXLOG line.

Counters come first: on a channel that beacons 50 times a second a sample ring
cannot prove whether a handful of frames arrived, a counter can.

Usage: c5verify.py COM10 COM5
"""

import sys
import time

import serial


def open_port(name):
    ser = serial.Serial(name, 115200, timeout=0.2)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.5)
    ser.reset_input_buffer()
    return ser


def send(ser, line):
    ser.write(line.encode() + b"\r\n")
    time.sleep(0.3)


def drain(ser, seconds):
    deadline = time.time() + seconds
    raw = bytearray()
    while time.time() < deadline:
        chunk = ser.read(4096)
        if chunk:
            raw.extend(chunk)
    return raw.decode("utf-8", "replace")


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mon = open_port(sys.argv[1])
    inj = open_port(sys.argv[2])

    send(mon, "PING")
    send(inj, "PING")
    print("=== ping ===")
    print("C5 :", drain(mon, 1.0).strip())
    print("ESP:", drain(inj, 1.0).strip().splitlines()[-1:])

    # MON clears the counters, so every round below describes exactly its window.
    send(mon, "MON 12 60")
    print("=== monitor ===")
    print(drain(mon, 1.0).strip())

    for kind in ("bar", "probe", "data"):
        # radio.chan holds for 30 s; refresh it or the injector hops back to ch 1
        # by the time the later rounds run.
        send(inj, "radio.chan ch=12")
        send(inj, "radio.tx_bench count=60 gap=20 kind=%s unicast=false" % kind)
        print("inj bench %-5s ->" % kind, drain(inj, 1.6).strip().splitlines()[-1:])
        send(mon, "RXMIX")
        print("=== C5 mix (%s) ===" % kind)
        print(drain(mon, 1.5).strip())

    mon.close()
    inj.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
