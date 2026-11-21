"""用 C5 上的老工程固件确认大帧真的完整出空口（不同代码库的第三方视角）。

Usage: bigframe_c5.py COM10 COM5
"""

import sys
import time

import serial


def open_port(name):
    ser = serial.Serial(name, 115200, timeout=0.2)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.4)
    ser.reset_input_buffer()
    return ser


def drain(ser, seconds):
    deadline = time.time() + seconds
    raw = bytearray()
    while time.time() < deadline:
        chunk = ser.read(4096)
        if chunk:
            raw.extend(chunk)
    return raw.decode("utf-8", "replace")


def send(ser, line, wait=0.4):
    ser.write(line.encode() + b"\r\n")
    time.sleep(wait)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mon = open_port(sys.argv[1])
    inj = open_port(sys.argv[2])

    send(mon, "MON 12 40", 1.0)
    print(drain(mon, 1.0).strip())

    send(inj, "radio.chan ch=12", 1.0)
    drain(inj, 0.8)
    send(inj, "radio.tx_bench count=3 gap=250 kind=data pad=1440 unicast=false", 0.4)
    print("inj:", "\n      ".join(drain(inj, 2.5).strip().splitlines()[-3:]))

    send(mon, "RXLOG", 0.4)
    text = drain(mon, 8.0)
    hits = [l for l in text.splitlines() if "type=2" in l and "len=1482" in l]
    print("C5 看到的大帧（len=1482 = 1478 + 4 字节 FCS）：")
    for line in hits:
        print("  ", line)
    if not hits:
        print("   没抓到，可能被 RXLOG 的环形缓冲挤掉了")

    mon.close()
    inj.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
