"""Does the raw TX path support HT at all?

Sends a 26-byte QoS Null under a given startup rate and reads back what the
sniffer saw in the PHY header. A 54M round runs in the same firmware so a
"nothing worked" result cannot be blamed on the rate config itself.

Usage: htprobe.py COM5 COM6
"""

import sys
import time

import serial

TA = "02:00:00:06:00:01"
TAIL = " - "


class Board:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.05)
        self.ser.dtr = False
        self.ser.rts = False
        time.sleep(0.4)
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
        self.ser.write((line + "\r\n").encode())
        return self.pump(wait)


def rates_in(lines):
    out = {}
    samples = []
    for line in lines:
        if "EVT monitor.rx" not in line or ("a2=" + TA) not in line:
            continue
        rate = ""
        for token in line.split():
            if token.startswith("rate="):
                rate = token.split("=", 1)[1]
        out.setdefault(rate, 0)
        out[rate] += 1
        if len(samples) < 3:
            samples.append(line)
    return out, samples


def run_round(inj, snf, rate, kind):
    print("   set rate ->", inj.cmd("radio.rate rate=%s" % rate, 0.8)[-2:])
    inj.ser.write(b"system.reset\r\n")
    inj.pump(3.6)
    inj.cmd("radio.chan ch=6", 1.0)
    print("   tx ->", inj.cmd("radio.tx_test kind=%s ta=%s" % (kind, TA), 0.4)[-2:])
    snf.cmd("monitor.chan ch=6", 0.8)
    snf.cmd("monitor.start kind=data ta=%s max=50" % TA, 0.8)
    for _ in range(6):
        inj.cmd("radio.tx_test kind=%s ta=%s" % (kind, TA), 0.25)
        time.sleep(0.1)
    lines = snf.pump(1.5)
    snf.cmd("monitor.stop", 0.5)
    return rates_in(lines)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    inj = Board(sys.argv[1])
    snf = Board(sys.argv[2])
    inj.pump(1.0)
    snf.pump(1.0)

    print("== MCS0 下 QoS Null ==")
    got, samples = run_round(inj, snf, "mcs0", "qosnull")
    print("   空口:", got if got else "一帧都没抓到")
    for line in samples:
        print("   ", line)

    print("== 54M 对照组（同一固件，确认配置链路有效） ==")
    got54, samples = run_round(inj, snf, "54m", "qosnull")
    print("   空口:", got54 if got54 else "一帧都没抓到")
    for line in samples:
        print("   ", line)

    inj.cmd("radio.rate rate=default", 0.6)
    inj.close()
    snf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
