#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
"""BLE 空口校验：一块板泛洪，另一块板扫描，确认广播真的按预期形状上了空气。

用法：
    python tools/blecheck.py COM5 COM7 [--seconds 8]

两块板刷同一份开了 BLE 的固件（`CONFIG_WB_BLE=y`）。第一块当攻击板，第二块
当观察板。检查项：弹窗模板字节、泛洪启动、攻击板轮换计数、观察板收到的广播
报告数与设备数、停手后广播占用者归还。

只做一次短跑，不做长时压力；长跑用 `lab/` 或手动执行。测完两边都停掉。
"""

import sys
import time

try:
    import serial
except ImportError:
    print("需要 pyserial：pip install pyserial")
    sys.exit(2)


class Board:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.05)
        # CH340 会被 DTR/RTS 按进复位/下载模式，打开后立刻放下
        self.ser.setDTR(False)
        self.ser.setRTS(False)
        self.buf = ""

    def close(self):
        self.ser.close()

    def pump(self, seconds):
        t0 = time.time()
        while time.time() - t0 < seconds:
            data = self.ser.read(8192)
            if data:
                self.buf += data.decode("utf-8", "replace")
        lines = []
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            line = line.strip("\r")
            if line:
                lines.append(line)
        return lines

    def cmd(self, line, wait=1.0):
        self.ser.reset_input_buffer()
        self.buf = ""
        self.ser.write((line + "\r\n").encode())
        return self.pump(wait)

    def send(self, line):
        self.ser.write((line + "\r\n").encode())


def field(lines, key):
    for line in lines:
        for token in line.split():
            if token.startswith(key + "="):
                return token.split("=", 1)[1]
    return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    seconds = 8
    for i, a in enumerate(sys.argv[1:]):
        if a == "--seconds" and i + 2 <= len(sys.argv[1:]):
            seconds = int(sys.argv[1:][i + 1])
    if len(args) < 2:
        print(__doc__)
        return 2

    attacker = Board(args[0])
    observer = Board(args[1])
    passed = 0
    failed = 0

    def check(name, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
            print("  [PASS] %s" % name)
        else:
            failed += 1
            print("  [FAIL] %s  %s" % (name, detail))

    try:
        time.sleep(1.5)
        attacker.pump(1.0)
        observer.pump(1.0)

        out = attacker.cmd("blespam.list")
        body = "\n".join(out)
        if "unknown object" in body:
            print("攻击板固件没有 blespam（BLE 没编进来）")
            return 3
        check("模板表非空", "templates n=" in body and "apple_airpods" in body, repr(out[:3]))

        out = attacker.cmd("blespam.test mode=popup template=apple_airpods")
        body = "\n".join(out)
        check("弹窗帧 31 字节", "adv len=31" in body, repr(out[:3]))
        check(
            "弹窗帧字节",
            "hex=1eff4c0007190120020c0e0a0c0e0a" in body,
            repr(out[:3]),
        )

        observer.cmd("ble.scan action=clear")
        observer.send("ble.scan action=start duration=%d" % ((seconds + 4) * 1000))
        observer.pump(0.5)

        out = attacker.cmd("blespam.start mode=flood cycle=50")
        check("泛洪启动", "OK blespam.start" in "\n".join(out), repr(out[:3]))

        time.sleep(seconds)

        info = attacker.cmd("ble.info")
        cycles = field(info, "cycles")
        owner = field(info, "owner")
        check("攻击板在轮换", cycles is not None and int(cycles) > 0, "cycles=%s" % cycles)
        check("广播占用者是 blespam", owner == "blespam", "owner=%s" % owner)

        out = attacker.cmd("blespam.stop")
        check("泛洪停止", "OK blespam.stop" in "\n".join(out), repr(out[:3]))

        out = observer.cmd("ble.scan action=stop")
        peers = observer.cmd("ble.scan action=list")
        scan_reports = field(observer.cmd("ble.info"), "scan_reports")
        n = field(out, "peers")
        print("  observer: peers=%s scan_reports=%s" % (n, scan_reports))
        check(
            "观察板收到广播",
            scan_reports is not None and int(scan_reports) > 0,
            "scan_reports=%s" % scan_reports,
        )
        check("观察板设备表非空", n is not None and int(n) > 0, "peers=%s" % n)

        time.sleep(0.5)
        info = attacker.cmd("ble.info")
        check("停手后广播占用者归还", field(info, "owner") in ("-", "gatt"), repr(info[:3]))
    finally:
        for board in (attacker, observer):
            try:
                board.send("blespam.stop")
                board.send("ble.scan action=stop")
            except Exception:
                pass
            board.close()

    print("blecheck: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
