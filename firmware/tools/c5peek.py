"""Open the C5 over USB-Serial-JTAG and dump whatever it prints.

Usage: c5peek.py COM10 [seconds] [line-to-send]...

The DTR/RTS pair is what puts the chip into download mode, so both are driven
low before reading. Lines given on the command line are sent after the board
has had a second to boot.
"""

import sys
import time

import serial


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    port = sys.argv[1]
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
    commands = sys.argv[3:]

    ser = serial.Serial(port, 115200, timeout=0.2)
    ser.dtr = False
    ser.rts = False
    time.sleep(1.0)
    ser.reset_input_buffer()

    for cmd in commands:
        ser.write(cmd.encode() + b"\r\n")
        time.sleep(0.4)

    deadline = time.time() + seconds
    raw = bytearray()
    while time.time() < deadline:
        chunk = ser.read(4096)
        if chunk:
            raw.extend(chunk)
    ser.close()

    sys.stdout.buffer.write(raw)
    if raw and not raw.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    print("---", len(raw), "bytes ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
