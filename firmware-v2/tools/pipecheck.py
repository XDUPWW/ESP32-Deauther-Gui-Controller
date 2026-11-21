#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
"""用 C5 的 pcap 管道核对注入速率与帧形状。

已废弃：C5 现在刷的是本仓库自己的监控固件，SDR 管道源不存在了。
速率核对改用 tools/ratecheck.py（COM5 注入、COM6 按 TA 过滤读 rate=）。

用法：
    python tools/pipecheck.py --port COM5 [--channel 12] [--pipe \\\\.\\pipe\\esp_sdr_wifi]

速率是启动期配置（官方只支持在 esp_wifi_init() 之后、esp_wifi_start() 之前设置），
所以每验证一档都要 `radio.rate` + `system.reset` + 等启动。

管道只在固件启动时写过一次 pcap 全局头，之后每次连接拿到的可能是裸记录流，
所以这里按记录边界重同步（0..15 以及跳过 24 字节全局头两种情况都试）。

关于速率字段：这块 C5 往 radiotap 的 Rate 里写的是 ESP 的 PHY rate 编码
（0x00/0x01/0x02/0x03 = 1/2/5.5/11 Mbps），OFDM 档一律报 1.0，
且高码率帧本身也大量丢，所以 6~54 Mbps 只能记 skip。
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

PHY_CODE_MBPS = {
    0x00: 1.0, 0x01: 2.0, 0x02: 5.5, 0x03: 11.0,
    0x05: 2.0, 0x06: 5.5, 0x07: 11.0,
    0x08: 48.0, 0x09: 24.0, 0x0A: 12.0, 0x0B: 6.0,
    0x0C: 9.0, 0x0D: 18.0, 0x0E: 36.0, 0x0F: 54.0,
}

RADIO_FIELDS = {
    0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (4, 2), 4: (2, 1), 5: (1, 1), 6: (1, 1),
    7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1),
    14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1), 18: (8, 4), 19: (3, 1), 20: (8, 4),
    21: (12, 2), 22: (12, 8), 23: (12, 2), 24: (12, 2),
}

CCK_RATES = [("1m", 1.0), ("2m", 2.0), ("5m5", 5.5), ("11m", 11.0)]
OFDM_RATES = [("6m", 6.0), ("24m", 24.0), ("54m", 54.0)]
TA = "02:00:00:05:00:01"


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
                "len": len(frame) - 4,  # 这块抓包端把 FCS 也算进长度
                "a1": frame[4:10].hex(":"),
                "a2": frame[10:16].hex(":"),
                "rate": rate,
            })
        position += 16 + incl
    return frames, bad


def best_parse(blob):
    best = None
    for offset in list(range(16)) + list(range(24, 40)):
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

    def close(self):
        self.stop = True
        self.thread.join(3.0)

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


class Device:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.05)
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

    def reboot(self, rate):
        self.cmd("radio.rate rate=%s" % rate, 0.8)
        self.ser.write(b"system.reset\r\n")
        self.pump(4.0)
        self.cmd("radio.chan ch=%d" % CHANNEL, 1.5)


CHANNEL = 12


def capture_burst(device, pipe, inject_line, times=6):
    # 这条管道一次只服务一个读端，上一个连接没退干净就会 Invalid argument，
    # 所以失败要重试，而且重试时必须重新开一次连接。
    for attempt in range(3):
        capture = Capture(pipe)
        capture.start()
        time.sleep(0.8)
        if capture.error:
            capture.close()
            print("  管道占用，重试 %d/3" % (attempt + 1))
            time.sleep(1.0)
            continue
        for _ in range(times):
            device.cmd(inject_line, 0.3)
            time.sleep(0.2)
        time.sleep(1.0)
        capture.close()
        frames = best_parse(capture.blob())
        if frames:
            return frames
        time.sleep(0.5)
    return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", default="COM5")
    parser.add_argument("--pipe", default="\\\\.\\pipe\\esp_sdr_wifi")
    parser.add_argument("--channel", default="12")
    args = parser.parse_args()

    global CHANNEL
    CHANNEL = int(args.channel)

    device = Device(args.port)
    device.pump(2.5)

    passed = failed = skipped = 0

    print("== CCK 速率（启动期配置，逐档重启） ==")
    for name, mbps in CCK_RATES:
        device.reboot(name)
        frames = [f for f in capture_burst(device, args.pipe,
                                           "radio.tx_test kind=probe ta=%s" % TA)
                  if f["a2"] == TA]
        if not frames:
            print("  [FAIL] %-4s 没抓到" % name)
            failed += 1
            continue
        rate = frames[0]["rate"]
        ok = rate is not None and abs(rate - mbps) < 0.01
        print("  [%s] %-4s 期望 %4.1f，radiotap %s，抓到 %d 帧" %
              ("PASS" if ok else "FAIL", name, mbps,
               "无" if rate is None else "%.1f" % rate, len(frames)))
        passed += ok
        failed += 0 if ok else 1

    print("== OFDM 速率（抓包端报不出，仅记录） ==")
    for name, mbps in OFDM_RATES:
        device.reboot(name)
        frames = [f for f in capture_burst(device, args.pipe,
                                           "radio.tx_test kind=probe ta=%s" % TA)
                  if f["a2"] == TA]
        observed = sorted({"无" if f["rate"] is None else "%.1f" % f["rate"] for f in frames})
        print("  [SKIP] %-4s 期望 %4.1f，抓到 %d 帧，报出 %s" %
              (name, mbps, len(frames), observed if observed else "无"))
        skipped += 1

    print("== 控制帧 + 数据帧（默认速率） ==")
    device.reboot("default")
    frames = capture_burst(device, args.pipe,
                           "radio.tx_test kind=bar ta=%s tid=3 ssn=999" % TA)
    bars = [f for f in frames if f["a2"] == TA and f["type"] == 1]
    if bars:
        frame = bars[0]
        ok = frame["subtype"] == 8 and frame["len"] == 20 and frame["a1"] == "ff:ff:ff:ff:ff:ff"
        print("  [%s] BAR subtype=%d len=%d a1=%s" %
              ("PASS" if ok else "FAIL", frame["subtype"], frame["len"], frame["a1"]))
        passed += ok
        failed += 0 if ok else 1
    else:
        print("  [FAIL] BAR 没抓到")
        failed += 1

    frames = capture_burst(device, args.pipe, "radio.tx_test kind=data ta=%s" % TA)
    datas = [f for f in frames if f["a2"] == TA and f["type"] == 2]
    if datas:
        frame = datas[0]
        ok = frame["subtype"] == 8 and frame["len"] == 38
        print("  [%s] data subtype=%d len=%d" % ("PASS" if ok else "FAIL", frame["subtype"],
                                                 frame["len"]))
        passed += ok
        failed += 0 if ok else 1
    else:
        print("  [FAIL] data 没抓到")
        failed += 1

    device.cmd("radio.rate rate=default", 0.6)
    print("\n%d passed, %d failed, %d skipped" % (passed, failed, skipped))
    device.close()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
