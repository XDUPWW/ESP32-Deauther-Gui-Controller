#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
"""跨板核对注入速率：一块板按启动期配置注入，另一块板用混杂回调读元数据。

用法：
    python tools/ratecheck.py COM5 COM6 [--channel 6]

速率是启动期配置（官方只支持 esp_wifi_init() 之后、esp_wifi_start() 之前设置），
所以每一档都要写 NVS + 重启。收包侧的速率来自 wifi_pkt_rx_ctrl_t：
legacy 帧看 rate 索引（0..11），11n 帧看 mcs + sgi。
"""

import sys
import time

import serial

TA = "02:00:00:06:00:01"

LEGACY = [("1m", 1.0), ("2m", 2.0), ("5m5", 5.5), ("11m", 11.0),
          ("6m", 6.0), ("9m", 9.0), ("12m", 12.0), ("18m", 18.0),
          ("24m", 24.0), ("36m", 36.0), ("48m", 48.0), ("54m", 54.0)]
HT = [("mcs0", "mcs0", 6.5), ("mcs1", "mcs1", 13.0), ("mcs2", "mcs2", 19.5),
      ("mcs3", "mcs3", 26.0), ("mcs4", "mcs4", 39.0), ("mcs5", "mcs5", 52.0),
      ("mcs6", "mcs6", 58.5), ("mcs7", "mcs7", 65.0)]


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

    def cmd(self, line, wait=1.0):
        self.ser.write((line + "\r\n").encode())
        return self.pump(wait)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    inj_port, snf_port = sys.argv[1], sys.argv[2]
    channel = "6"
    if "--channel" in sys.argv:
        channel = sys.argv[sys.argv.index("--channel") + 1]
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].split(",")

    inj = Board(inj_port, reset=False)
    snf = Board(snf_port, reset=False)
    inj.pump(1.0)
    snf.pump(1.0)

    passed = failed = 0
    print("== 速率（收包侧读 wifi_pkt_rx_ctrl_t） ==")
    for name, expect in LEGACY + [(n, mbps) for n, _, mbps in HT]:
        if only and name not in only:
            continue
        # 注入板：写 NVS 后重启，让速率在 esp_wifi_start() 之前生效
        inj.cmd("radio.rate rate=%s" % name, 0.8)
        inj.ser.write(b"system.reset\r\n")
        inj.pump(4.0)
        inj.cmd("radio.chan ch=%s" % channel, 1.2)

        # 嗅探板：同信道 + 按 TA 过滤。开抓之前把上一档积压的输出排干净，否则
        # 上一档的帧会串进来，判定时 got[0] 根本不是这一档的。
        snf.cmd("monitor.chan ch=%s" % channel, 1.0)
        snf.pump(0.4)
        snf.buf = ""
        snf.cmd("monitor.start kind=all ta=%s max=50" % TA, 1.0)
        snf.pump(0.2)
        snf.buf = ""

        # 管理帧多半被驱动按 legacy 发，MCS 档改用数据帧验证
        kind = "qosnull" if name.startswith("mcs") else "probe"
        for _ in range(8):
            inj.cmd("radio.tx_test kind=%s ta=%s" % (kind, TA), 0.3)
            time.sleep(0.15)
        lines = snf.pump(1.8)
        snf.cmd("monitor.stop", 0.6)

        got = [l for l in lines if "EVT monitor.rx" in l and ("a2=" + TA) in l]
        if not got:
            print("  [FAIL] %-4s 没抓到" % name)
            failed += 1
            continue
        rate_field = ""
        for token in got[0].split():
            if token.startswith("rate="):
                rate_field = token.split("=", 1)[1]
        ok = False
        if name.startswith("mcs"):
            ok = rate_field.startswith("mcs") and rate_field[3:4] == name[3:4]
        else:
            try:
                ok = abs(float(rate_field.split("M")[0]) - expect) < 0.01
            except ValueError:
                ok = False
        print("  [%s] %-4s 期望 %-5s 空口 %s（抓到 %d 帧）" %
              ("PASS" if ok else "FAIL", name,
               ("%.1fM" % expect) if not name.startswith("mcs") else name, rate_field, len(got)))
        passed += ok
        failed += 0 if ok else 1

    inj.cmd("radio.rate rate=default", 0.6)
    print("\n%d passed, %d failed" % (passed, failed))
    inj.close()
    snf.close()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
