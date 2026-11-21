"""验证 sta_list 三种来源的切换语义。

Usage: aplist.py COM6
"""

import sys
import time

import serial


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    ser = serial.Serial(sys.argv[1], 115200, timeout=0.2)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.5)
    ser.reset_input_buffer()

    def cmd(line, wait=1.0):
        ser.write((line + "\r\n").encode())
        deadline = time.time() + wait
        buf = bytearray()
        while time.time() < deadline:
            chunk = ser.read(4096)
            if chunk:
                buf.extend(chunk)
        return buf.decode("utf-8", "replace")

    print("1) 先攒一点被动表")
    cmd("monitor.chan ch=6", 0.8)
    cmd("monitor.start kind=all max=20", 4.0)
    head = cmd("radio.sta_list src=auto", 1.2).splitlines()
    print("   auto  ->", head[0] if head else "(空)")

    print("2) 起 softAP")
    print("  ", "\n   ".join(cmd("radio.ap ssid=v2test ch=6", 3.0).strip().splitlines()))

    print("3) 起了 AP 之后（应走 AP 表，没客户端就是 0）")
    head = cmd("radio.sta_list src=auto", 1.2).splitlines()
    print("   auto  ->", head[0] if head else "(空)")

    print("4) 强制被动表（应该还是旧数据）")
    head = cmd("radio.sta_list src=passive", 1.2).splitlines()
    print("   passive ->", head[0] if head else "(空)")

    print("5) 停 AP")
    print("  ", "\n   ".join(cmd("radio.ap_stop", 3.0).strip().splitlines()))

    print("6) 停完再查 auto（应回到被动表）")
    head = cmd("radio.sta_list src=auto", 1.2).splitlines()
    print("   auto  ->", head[0] if head else "(空)")

    ser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
