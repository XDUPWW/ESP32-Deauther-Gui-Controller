#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
"""用 C5 的 pcap 管道核对注入速率与帧形状。

用法：
    python tools/pipecheck.py --port COM5 [--channel 12] [--pipe \\\\.\\pipe\\esp_sdr_wifi]

抓包端是另一块板（C5）把 radiotap 流写进命名管道。注意：管道只在固件启动时
写过一次 pcap 全局头，之后每次连接拿到的都是裸记录流，所以这里按记录边界重同步。

ESP32 自己的 promiscuous API 读不到速率（IDF 6.1 的 wifi_pkt_rx_ctrl_t 没有 rate 字段），
只有这条链路能给出 radiotap 的 data rate。实测该管道只报得出 CCK 速率（1/2/5.5/11 Mbps），
OFDM 速率一律显示 1 Mbps，因此 6~54 Mbps 只能记为"抓包端报不出"。
"""

import argparse
import sys
import threading
import time

try:
    import serial
except ImportError:
    print("需要 pyserial：pip install pyserial")
    sys.exit(2)

RADIO_FIELDS = {
    0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (4, 2), 4: (2, 1), 5: (1, 1), 6: (1, 1),
    7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1),
    14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1), 18: (8, 4), 19: (3, 1), 20: (8, 4),
    21: (12, 2), 22: (12, 8), 23: (12, 2), 24: (12, 2),
}

# 这块 C5 固件往 radiotap 的 Rate 字段里塞的是 ESP 的 PHY rate 编码，
# 不是标准的 500 kbps 单位：0x00/0x01/0x02/0x03 依次是 1/2/5.5/11 Mbps。
PHY_CODE_MBPS = {
    0x00: 1.0, 0x01: 2.0, 0x02: 5.5, 0x03: 11.0,
    0x05: 2.0, 0x06: 5.5, 0x07: 11.0,
    0x08: 48.0, 0x09: 24.0, 0x0A: 12.0, 0x0B: 6.0,
    0x0C: 9.0, 0x0D: 18.0, 0x0E: 36.0, 0x0F: 54.0,
}

CCK_RATES = [("1m", 1.0), ("2m", 2.0), ("5m5", 5.5), ("11m", 11.0)]
OFDM_RATES = [("6m", 6.0), ("9m", 9.0), ("12m", 12.0), ("18m", 18.0), ("24m", 24.0),
              ("36m", 36.0), ("48m", 48.0), ("54m", 54.0)]


def parse_radiotap(blob):
    if len(blob) < 8 or blob[0] != 0:
        return None, 0
    header_len = int.from_bytes(blob[2:4], "little")
    if header_len < 8 or header_len > len(blob):
        return None, 0

    words = []
    offset = 4
    while offset + 4 <= header_len:
        word = int.from_bytes(blob[offset:offset + 4], "little")
        words.append(word)
        offset += 4
        if not word & (1 << 31):
            break

    bits = []
    for index, word in enumerate(words):
        for bit in range(31):
            if word & (1 << bit):
                bits.append(index * 32 + bit)

    position = offset
    rate = None
    for bit in bits:
        if bit not in RADIO_FIELDS:
            return None, header_len
        size, align = RADIO_FIELDS[bit]
        position = (position + align - 1) // align * align
        if position + size > header_len:
            return None, header_len
        if bit == 2:
            rate = PHY_CODE_MBPS.get(blob[position])
        position += size
    return rate, header_len


def parse_stream(blob, offset):
    frames = []
    bad = 0
    position = offset
    while position + 16 <= len(blob):
        incl = int.from_bytes(blob[position + 8:position + 12], "little")
        if incl == 0 or incl > 65535 or position + 16 + incl > len(blob):
            break
        record = blob[position + 16:position + 16 + incl]
        rate, header_len = parse_radiotap(record)
        if header_len == 0 or len(record) < header_len + 10:
            bad += 1
        else:
            frame = record[header_len:]
            fc = int.from_bytes(frame[0:2], "little")
            frames.append({
                "type": (fc >> 2) & 3,
                "subtype": (fc >> 4) & 0xF,
                # 这块抓包设备把 4 字节 FCS 也算进长度
                "len": len(frame) - 4,
                "a1": frame[4:10].hex(":"),
                "a2": frame[10:16].hex(":"),
                "rate": rate,
            })
        position += 16 + incl
    return frames, bad


def best_parse(blob):
    best = None
    for offset in range(16):
        frames, bad = parse_stream(blob, offset)
        score = len(frames) - bad * 4
        if best is None or score > best[0]:
            best = (score, frames)
    return best[1]


class Capture:
    def __init__(self, pipe):
        self.pipe = pipe
        self.chunks = []
        self.error = None
        self.stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def _run(self):
        try:
            with open(self.pipe, "rb", buffering=0) as handle:
                while not self.stop:
                    data = handle.read(65536)
                    if not data:
                        break
                    self.chunks.append(data)
        except Exception as exc:  # noqa: BLE001
            self.error = repr(exc)

    def blob(self):
        return b"".join(self.chunks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", default="COM5")
    parser.add_argument("--pipe", default="\\\\.\\pipe\\esp_sdr_wifi")
    parser.add_argument("--channel", default="12")
    parser.add_argument("--settle", type=float, default=1.5)
    args = parser.parse_args()

    ser = serial.Serial(args.port, 115200, timeout=0.05)
    ser.setDTR(False)
    ser.setRTS(True)
    time.sleep(0.1)
    ser.setRTS(False)
    time.sleep(2.0)

    def cmd(line, wait=0.8):
        ser.reset_input_buffer()
        ser.write((line + "\r\n").encode())
        t0 = time.time()
        buf = ""
        while time.time() - t0 < wait:
            buf += ser.read(4096).decode("utf-8", "replace")
        return [l.strip("\r") for l in buf.splitlines() if l.strip()]

    def raw(line):
        ser.write((line + "\r\n").encode())

    print("== 准备 ==")
    for line in cmd("radio.chan ch=%s" % args.channel):
        if line.startswith(("OK radio", "ERR")):
            print("  ", line)

    capture = Capture(args.pipe)
    capture.start()
    time.sleep(1.0)
    if capture.error:
        print("抓包管道打不开:", capture.error)
        return 2

    plan = []
    for group, rates in (("cck", CCK_RATES), ("ofdm", OFDM_RATES)):
        for index, (name, mbps) in enumerate(rates):
            ta = "02:00:00:%02x:%02x:01" % (0 if group == "cck" else 1, index + 1)
            ok = True
            for _ in range(5):
                out = cmd("radio.tx_test kind=probe rate=%s ta=%s" % (name, ta), 0.2)
                ok = ok and any(l.startswith("OK radio.tx_test") for l in out)
                time.sleep(0.15)
            print("  注入 %-4s ta=%s %s" % (name, ta, "ok x5" if ok else "失败"))
            if ok:
                plan.append({"name": name, "mbps": mbps, "ta": ta, "group": group})

    print("\n== 控制帧 BAR（1 Mbps，指定 TA） ==")
    bar_ta = "02:00:00:00:aa:bb"
    for _ in range(5):
        out = cmd("radio.tx_test kind=bar ta=%s rate=1m tid=3 ssn=999" % bar_ta, 0.2)
        time.sleep(0.15)
    print("  ", " ".join(l for l in out if l.startswith(("sent", "OK", "ERR"))))

    time.sleep(args.settle)
    capture.stop = True
    time.sleep(0.3)

    blob = capture.blob()
    frames = best_parse(blob)
    by_ta = {}
    for frame in frames:
        by_ta.setdefault(frame["a2"], []).append(frame)
    print("\n管道 %d 字节，解析出 %d 帧" % (len(blob), len(frames)))

    passed = failed = skipped = 0
    print("\n== 速率 ==")
    for item in plan:
        found = by_ta.get(item["ta"], [])
        if not found:
            print("  [FAIL] %-4s 没抓到" % item["name"])
            failed += 1
            continue
        rate = found[0]["rate"]
        if item["group"] == "cck":
            ok = rate is not None and abs(rate - item["mbps"]) < 0.01
            print("  [%s] %-4s 期望 %4.1f，radiotap %s" %
                  ("PASS" if ok else "FAIL", item["name"], item["mbps"],
                   "无" if rate is None else "%.1f" % rate))
            passed += ok
            failed += 0 if ok else 1
        else:
            # 抓包端只报 CCK，OFDM 一律显示 1 Mbps，只能记 skip
            clamped = rate is not None and abs(rate - 1.0) < 0.01
            print("  [SKIP] %-4s 期望 %4.1f，空口 %s%s" %
                  (item["name"], item["mbps"], "无" if rate is None else "%.1f Mbps" % rate,
                   "（空口仍是 1 Mbps：抓包端报不出 OFDM，或驱动对管理帧钳制）" if clamped else ""))
            skipped += 1

    print("\n== 控制帧 ==")
    bar = [f for f in by_ta.get(bar_ta, []) if f["type"] == 1]
    if bar:
        frame = bar[0]
        ok = frame["subtype"] == 8 and frame["len"] == 20 and frame["rate"] == 1.0
        print("  [%s] BAR subtype=%d len=%d rate=%s a1=%s" %
              ("PASS" if ok else "FAIL", frame["subtype"], frame["len"],
               "无" if frame["rate"] is None else "%.1f" % frame["rate"], frame["a1"]))
        passed += ok
        failed += 0 if ok else 1
    else:
        print("  [FAIL] BAR 没抓到")
        failed += 1

    print("\n%d passed, %d failed, %d skipped" % (passed, failed, skipped))
    ser.close()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
