#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
"""跨板空口校验：一块板注入，另一块板嗅探，确认帧真的按预期的形状上了空气。

用法：
    python tools/aircheck.py COM5 COM6 [--channel 6]

两块板刷同一份固件。注入板不做别的，嗅探板只跑 monitor。检查项：
控制帧 BAR（20 字节）、管理帧 probe request（36 字节）、指定 TA、随机 TA、
单播节流、广播突发。

测完会关掉两边的嗅探与信道租约，板子留在可用状态。
"""

import sys
import time

try:
    import serial
except ImportError:
    print("需要 pyserial：pip install pyserial")
    sys.exit(2)

OK_PREFIX = ("OK ", "ERR ")


class Board:
    def __init__(self, port, reset=True):
        self.ser = serial.Serial(port, 115200, timeout=0.05)
        if reset:
            self.ser.setDTR(False)
            self.ser.setRTS(True)
            time.sleep(0.1)
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

    def cmd(self, line, wait=1.2):
        self.ser.reset_input_buffer()
        self.buf = ""
        self.ser.write((line + "\r\n").encode())
        return self.pump(wait)

    def raw(self, line):
        self.ser.write((line + "\r\n").encode())


def field(lines, key):
    for line in lines:
        for token in line.split():
            if token.startswith(key + "="):
                return token.split("=", 1)[1]
    return None


def int_field(lines, key):
    value = field(lines, key)
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


class Report:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=""):
        self.rows.append((name, ok))
        mark = "PASS" if ok else "FAIL"
        print("  [%s] %s%s" % (mark, name, ("  " + detail) if detail and not ok else ""))

    def summary(self):
        passed = sum(1 for _, ok in self.rows if ok)
        print("\n%d passed, %d failed" % (passed, len(self.rows) - passed))
        return all(ok for _, ok in self.rows)


def rx_lines(lines, needle="EVT monitor.rx"):
    return [l for l in lines if needle in l]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    inj_port, snf_port = sys.argv[1], sys.argv[2]
    channel = "6"
    if "--channel" in sys.argv:
        channel = sys.argv[sys.argv.index("--channel") + 1]

    report = Report()
    inj = Board(inj_port)
    snf = Board(snf_port)
    inj.pump(2.5)
    snf.pump(2.5)

    print("== 准备 ==")
    inj.cmd("radio.chan ch=%s" % channel)
    snf.cmd("monitor.chan ch=%s" % channel)
    inj_mac = field(inj.cmd("radio.info"), "mac")
    snf_mac = field(snf.cmd("radio.info"), "mac")
    report.check("两块板都拿到 mac", bool(inj_mac) and bool(snf_mac), "%s / %s" % (inj_mac, snf_mac))
    report.check("两块板 mac 不同", inj_mac != snf_mac)

    print("== 控制帧 BAR（20 字节，指定 TA） ==")
    ta = "02:aa:bb:cc:dd:ee"
    snf.cmd("monitor.start kind=ctrl ta=%s" % ta)
    frames = []
    for _ in range(3):
        out = inj.cmd("radio.tx_test kind=bar ta=%s tid=3 ssn=999" % ta)
        report.check("注入返回成功", any(l.startswith("OK radio.tx_test") for l in out), repr(out))
        time.sleep(0.2)
        frames = rx_lines(snf.pump(1.5))
        if frames:
            break
    report.check("嗅探到 1 帧", len(frames) >= 1, repr(frames))
    if frames:
        frame = frames[0]
        report.check("类型是控制帧子类型 8", "t=ctrl s=8" in frame, frame)
        report.check("长度 20 字节", "len=20" in frame, frame)
        report.check("RA 是广播", "a1=ff:ff:ff:ff:ff:ff" in frame, frame)
        report.check("TA 是我们指定的", "a2=" + ta in frame, frame)
        report.check("控制帧不打 addr3", "a3=-" in frame, frame)

    print("== 管理帧 probe request（36 字节，指定 TA） ==")
    ta2 = "02:11:22:33:44:55"
    snf.cmd("monitor.start kind=mgmt ta=%s" % ta2)
    frames = []
    for _ in range(3):
        out = inj.cmd("radio.tx_test kind=probe ta=%s" % ta2)
        report.check("注入返回成功", any(l.startswith("OK radio.tx_test") for l in out), repr(out))
        time.sleep(0.2)
        frames = rx_lines(snf.pump(1.5))
        if frames:
            break
    report.check("嗅探到 1 帧", len(frames) >= 1, repr(frames))
    if frames:
        frame = frames[0]
        report.check("类型是管理帧子类型 4", "t=mgmt s=4" in frame, frame)
        report.check("长度 36 字节", "len=36" in frame, frame)
        report.check("TA 是我们指定的", "a2=" + ta2 in frame, frame)

    print("== 随机 TA ==")
    snf.cmd("monitor.start kind=ctrl")
    out = inj.cmd("radio.tx_test kind=bar ta=random")
    random_ta = field(out, "ta")
    # "ta=a2:.." 这种字段是 sent 行里的，另取一遍
    for line in out:
        for token in line.split():
            if token.startswith("ta="):
                random_ta = token.split("=", 1)[1]
    report.check("注入行里有 ta", bool(random_ta), repr(out))
    time.sleep(0.2)
    frames = [l for l in rx_lines(snf.pump(1.5)) if "s=8" in l]
    report.check("嗅探到 BAR", len(frames) >= 1, repr(frames))
    if random_ta and frames:
        report.check("空气上的 TA 就是随机的那个", any("a2=" + random_ta in l for l in frames),
                     repr(frames[:2]))
        first = int(random_ta.split(":")[0], 16)
        report.check("随机 TA 是本地管理单播", (first & 0x03) == 0x02, random_ta)

    print("== 单播节流（两帧紧挨着） ==")
    before = int_field(inj.cmd("radio.info"), "throttled")
    line = "radio.tx_test kind=bar ra=%s" % snf_mac
    inj.raw(line)
    inj.raw(line)
    inj.pump(1.5)
    after = int_field(inj.cmd("radio.info"), "throttled")
    report.check("第二帧被节流两次计数 +1", after == before + 1, "throttled %d -> %d" % (before, after))

    print("== 广播突发（60 帧，只受 20ms 广播节拍约束） ==")
    before_ok = int_field(inj.cmd("radio.info"), "ok")
    for _ in range(60):
        inj.raw("radio.tx_test kind=probe")
        time.sleep(0.03)  # 广播节拍 20ms，发太快会按设计被节流
    time.sleep(0.5)
    lines = inj.pump(1.0)
    sent = len([l for l in lines if "sent kind=probe" in l])
    report.check("60 帧都发出去了", sent >= 58, "sent=%d" % sent)
    after_ok = int_field(inj.cmd("radio.info"), "ok")
    report.check("发送计数器跟着涨", after_ok - before_ok == sent, "%d -> %d" % (before_ok, after_ok))

    print("== 收尾 ==")
    report.check("注入板没重启", "2nd stage" not in " ".join(inj.cmd("system.info")))
    snf.cmd("monitor.stop")
    inj.cmd("radio.release")

    inj.close()
    snf.close()
    return 0 if report.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
