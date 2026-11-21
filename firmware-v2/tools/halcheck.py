"""一次跑完 HAL 三项新能力的验证：大帧、广播节流、STA 表。

Usage: halcheck.py COM5 COM6
"""

import re
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
    inj = open_port(sys.argv[1])
    snf = open_port(sys.argv[2])

    send(inj, "radio.chan ch=6")
    mac = ""
    for line in drain(inj, 1.0).splitlines():
        hit = re.search(r"mac=([0-9a-f:]{17})", line)
        if hit:
            mac = hit.group(1)
    send(snf, "monitor.chan ch=6")
    drain(snf, 0.8)

    print("=== 1) 大帧：data pad=1440，帧长应 1478 ===")
    # 按 TA 过滤，否则 6 信道的背景流量会把这 3 帧挤出 max 配额
    send(snf, "monitor.start kind=data ta=%s max=200" % mac)
    send(inj, "radio.tx_bench count=3 gap=200 kind=data pad=1440 unicast=false")
    print("  inj:", "\n       ".join(drain(inj, 3.0).strip().splitlines()[-3:]))
    lines = drain(snf, 1.5).strip().splitlines()
    for line in lines:
        if "EVT monitor.rx" in line:
            print("  rx :", line)
    send(snf, "monitor.stop")

    print("=== 2) 广播节流：gap=0 连排 100 帧，应被压到 ~50fps 且不重启 ===")
    send(inj, "radio.tx_bench count=100 gap=0 kind=bar unicast=false")
    print("  inj:", "\n       ".join(drain(inj, 6.0).strip().splitlines()[-3:]))
    print("  alive:", drain(inj, 0.5).strip().splitlines()[-1:])

    print("=== 3) STA 表 ===")
    send(snf, "radio.sta_list src=passive")
    print(drain(snf, 1.5).strip())
    send(snf, "radio.sta_list src=auto")
    print(drain(snf, 1.0).strip())

    inj.close()
    snf.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
