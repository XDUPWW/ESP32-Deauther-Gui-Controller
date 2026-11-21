#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
"""板端自测：框架对象方法、参数校验、传输背压、界面插件、稳定性。

用法：
    python tools/selftest.py COM5
    python tools/selftest.py COM5 --keep   # 不触发复位，直接连当前会话
"""

import sys
import time

try:
    import serial
except ImportError:
    print("需要 pyserial：pip install pyserial")
    sys.exit(2)

OK_PREFIX = ("OK ", "ERR ")


class Device:
    def __init__(self, port, reset=True):
        self.ser = serial.Serial(port, 115200, timeout=0.05)
        if reset:
            self.ser.setDTR(False)
            self.ser.setRTS(True)
            time.sleep(0.1)
            self.ser.setRTS(False)
        self.buffer = ""

    def close(self):
        self.ser.close()

    def read_for(self, seconds):
        deadline = time.time() + seconds
        out = []
        while time.time() < deadline:
            data = self.ser.read(4096)
            if data:
                text = data.decode("utf-8", "replace")
                self.buffer += text
                out.append(text)
        return "".join(out)

    def send(self, line):
        self.ser.write((line + "\r\n").encode())

    def command(self, line, timeout=3.0):
        """发送一行，读到 OK/ERR 终止行为止，返回全部输出行。"""
        self.ser.reset_input_buffer()
        self.buffer = ""
        self.send(line)
        deadline = time.time() + timeout
        lines = []
        while time.time() < deadline:
            text = self.read_for(0.05)
            if text:
                self.buffer += ""
            while "\n" in self.buffer:
                raw, self.buffer = self.buffer.split("\n", 1)
                line_out = raw.strip("\r")
                lines.append(line_out)
                if line_out.startswith(OK_PREFIX):
                    return lines
        return lines


class Report:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=""):
        self.rows.append((name, ok, detail))
        mark = "PASS" if ok else "FAIL"
        print("  [%s] %s%s" % (mark, name, ("  " + detail) if detail and not ok else ""))

    def summary(self):
        passed = sum(1 for _, ok, _ in self.rows if ok)
        failed = len(self.rows) - passed
        print("\n%d passed, %d failed" % (passed, failed))
        return failed == 0


def expect(report, device, name, line, must=(), must_not=(), timeout=3.0):
    out = device.command(line, timeout)
    body = "\n".join(out)
    ok = True
    missing = [m for m in must if m not in body]
    if missing:
        ok = False
        report.check(name, False, "missing %r, got: %r" % (missing, out[:4]))
    hit = [m for m in must_not if m in body]
    if hit:
        ok = False
        report.check(name, False, "unexpected %r" % (hit,))
    if ok:
        report.check(name, True)
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    port = sys.argv[1]
    keep = "--keep" in sys.argv[2:]

    device = Device(port, reset=not keep)
    report = Report()

    print("== boot ==")
    boot = device.read_for(2.5)
    report.check("boot banner", "INFO boot" in boot, repr(boot[-200:]))
    report.check("display ready", "INFO display ready" in boot, repr(boot[-200:]))
    report.check("no panic in boot", "Guru Meditation" not in boot and "abort()" not in boot)

    print("== object methods ==")
    expect(report, device, "system.ping", "system.ping", must=("pong ms=", "OK system.ping"))
    expect(
        report,
        device,
        "system.info",
        "system.info",
        must=("idf=v6.1", "uptime_s=", "heap=", "min_heap=", "objects=5", "OK system.info"),
    )
    out = expect(report, device, "system.help", "system.help",
                 must=("system", "ping", "screen", "[count=1..4]", "OK system.help"))
    report.check(
        "help lists every object",
        all(any(obj in l for l in out) for obj in ("system", "ui", "radio", "scan", "monitor")),
        repr(out[:8]),
    )
    expect(report, device, "system.touch", "system.touch",
           must=("touch raw_x=", "raw_y=", "pressed=", "OK system.touch"))
    expect(report, device, "ui.status", "ui.status",
           must=("ready=1", "flush=", "heap=", "OK ui.status"))

    print("== argument validation ==")
    expect(report, device, "screen default", "ui.screen",
           must=("screen test armed count=4", "OK ui.screen"))
    expect(report, device, "screen count=1", "ui.screen count=1", must=("count=1",))
    expect(report, device, "screen count=5", "ui.screen count=5",
           must=("ERR ui.screen: count must be 1..4",))
    expect(report, device, "screen count=0", "ui.screen count=0",
           must=("count must be 1..4",))
    expect(report, device, "screen count=abc", "ui.screen count=abc",
           must=("count is not a number",))
    expect(report, device, "screen unknown arg", "ui.screen extra=1",
           must=("extra is not a parameter of screen",))
    expect(report, device, "unknown object", "bogus.ping", must=("unknown object",))
    expect(report, device, "unknown method", "system.nope", must=("unknown method",))
    expect(report, device, "bare token", "system.ping word", must=("expect key=value",))
    expect(report, device, "missing dot", "system", must=("expect object.method",))

    print("== transport edges ==")
    long_line = "system.ping " + ("x" * 300)
    expect(report, device, "overlong line", long_line, must=("line too long",))
    device.command("system.ping")
    report.check("recovers after overlong line", True)

    print("== backpressure (40 in a burst) ==")
    device.ser.reset_input_buffer()
    device.buffer = ""
    burst = 40
    for _ in range(burst):
        device.ser.write(b"system.ping\r\n")
    text = ""
    deadline = time.time() + 15
    while time.time() < deadline and text.count("OK system.ping") < burst:
        text += device.read_for(0.1)
    got = text.count("OK system.ping")
    report.check("burst delivers all %d commands" % burst, got == burst, "got %d" % got)

    print("== ui plugin ==")
    before = device.command("ui.status")
    for _ in range(6):
        device.command("system.ping")
    time.sleep(0.6)
    after = device.command("ui.status")

    def flush_of(lines):
        for line in lines:
            for token in line.split():
                if token.startswith("flush="):
                    try:
                        return int(token.split("=", 1)[1])
                    except ValueError:
                        return -1
        return -1

    f0, f1 = flush_of(before), flush_of(after)
    report.check("log mirror triggers redraw", f0 >= 0 and f1 > f0, "flush %d -> %d" % (f0, f1))

    print("== radio ==")
    info = expect(report, device, "radio.info", "radio.info",
                  must=("mac=", "ch=", "cc=CN", "tx ok=", "rx frames=", "OK radio.info"))
    report.check("radio has a mac", "mac=00:00:00:00:00:00" not in " ".join(info))

    print("== scan (active) ==")
    out = expect(report, device, "scan.ap", "scan.ap", must=("scan ap count=", "OK scan.ap"), timeout=20)
    count = 0
    for line in out:
        if "scan ap count=" in line:
            try:
                count = int(line.split("scan ap count=")[1].split()[0])
            except (IndexError, ValueError):
                count = 0
    report.check("active scan finds access points", count > 0, "count=%d" % count)
    expect(report, device, "scan.clear", "scan.clear", must=("cleared",))

    print("== channel arbitration ==")
    expect(report, device, "listen for lease", "scan.listen", must=("listening",), timeout=5)
    expect(report, device, "pinned channel denied while listening", "radio.chan ch=6",
           must=("channel busy with scan",))
    expect(report, device, "listen status", "scan.status",
           must=("listening=1", "owner=scan", "beacon=", "probe_resp="))

    print("== injection loop ==")
    expect(report, device, "inject probe request", "radio.tx_test",
           must=("sent kind=probe len=36", "OK radio.tx_test"))
    tx = device.command("radio.info")
    tx_ok = 0
    for line in tx:
        for token in line.split():
            if token.startswith("ok="):
                try:
                    tx_ok = int(token.split("=")[1])
                except ValueError:
                    tx_ok = 0
                break
    report.check("tx counter moved", tx_ok >= 1, "tx ok=%d" % tx_ok)

    got = 0
    deadline = time.time() + 12
    while time.time() < deadline:
        # 被动扫描在跳信道，probe 落到哪条信道是随机的：多发几次，
        # 迟早会落在某个 AP 的信道上。
        device.command("radio.tx_test")
        time.sleep(0.5)
        status = device.command("scan.status")
        for line in status:
            for token in line.split():
                if token.startswith("probe_resp="):
                    try:
                        got = max(got, int(token.split("=")[1]))
                    except ValueError:
                        pass
        if got > 0:
            break
    report.check("access points answer our probe request", got > 0, "probe_resp=%d" % got)

    expect(report, device, "stop listening", "scan.stop", must=("stopped",))
    expect(report, device, "channel free after stop", "radio.chan ch=6",
           must=("channel=6", "owner=radio"))
    expect(report, device, "release channel", "radio.release", must=("released",))
    expect(report, device, "radio diag", "radio.diag", must=("promisc=", "filter=0x", "cc=CN"))

    print("== monitor ==")
    expect(report, device, "monitor open", "monitor.start kind=ctrl",
           must=("monitor on kind=ctrl",), timeout=5)
    expect(report, device, "monitor status", "monitor.status", must=("on=1", "total=", "rx="))
    expect(report, device, "monitor close", "monitor.stop", must=("monitor off",))

    print("== screen flush path ==")

    def flush_now():
        return flush_of(device.command("ui.status"))

    base = flush_now()
    device.command("ui.screen count=1")
    time.sleep(1.0)
    one = flush_now()
    device.command("ui.screen count=4")
    time.sleep(2.2)
    four = flush_now()
    delta_one = one - base
    delta_four = four - one
    report.check("count=1 redraws the panel", delta_one > 0, "delta=%d" % delta_one)
    report.check("count=4 redraws more than count=1", delta_four > delta_one,
                 "delta1=%d delta4=%d" % (delta_one, delta_four))

    print("== stability ==")
    info_before = device.command("system.info")
    time.sleep(3)
    info_after = device.command("system.info")
    report.check("no reboot during run",
                 "2nd stage bootloader" not in "\n".join(info_after), repr(info_after[:3]))

    def field(lines, key):
        for line in lines:
            for token in line.split():
                if token.startswith(key + "="):
                    try:
                        return int(token.split("=", 1)[1])
                    except ValueError:
                        return -1
        return -1

    up0, up1 = field(info_before, "uptime_s"), field(info_after, "uptime_s")
    report.check("uptime advances", up0 >= 0 and up1 > up0, "%d -> %d" % (up0, up1))
    heap = field(info_after, "heap")
    report.check("heap above 40KB with wifi up", heap > 40 * 1024, "heap=%d" % heap)

    status = device.command("ui.status")
    report.check("ui still ready", any("ready=1" in l for l in status), repr(status[:3]))

    device.close()
    return 0 if report.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
