"""Inject with one board and watch the events another board prints.

Answers "did the frame leave the radio at all" before blaming the receiver.

Usage: rxcheck.py COM6 COM5 [ch]
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
    rx = open_port(sys.argv[1])
    tx = open_port(sys.argv[2])
    ch = sys.argv[3] if len(sys.argv) > 3 else "12"

    send(rx, "monitor.chan ch=%s" % ch)
    send(rx, "monitor.start kind=ctrl max=500")
    print("rx setup:", drain(rx, 1.0).strip())

    send(tx, "radio.chan ch=%s" % ch)
    send(tx, "radio.tx_bench count=100 gap=20 kind=bar unicast=false")
    print("tx:", drain(tx, 0.8).strip())

    print("=== rx saw ===")
    print(drain(rx, 5.0).strip())

    send(rx, "monitor.status")
    print("=== status ===")
    print(drain(rx, 1.0).strip())

    rx.close()
    tx.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
