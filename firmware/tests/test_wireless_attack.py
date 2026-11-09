"""无线攻击固件 + 上位机协议的测试套件。

覆盖：协议解析单元测试、固件功能测试、稳定性测试、压力测试、性能测试，
以及在启用 LVGL 界面时的启动/内存检查。

运行：
    set DEAUTHER_PORT=COM5
    python -m unittest discover -s tests -v
"""

import os
import statistics
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GUI_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "gui"))
sys.path.insert(0, GUI_DIR)

import protocol  # noqa: E402

PORT = os.environ.get("DEAUTHER_PORT", "COM5")
ESPTOOL_PY = os.environ.get(
    "ESPTOOL_PY", r"C:\Espressif\tools\python\v6.1\venv\Scripts\python.exe"
)


# --------------------------------------------------------------------------- unit


class ProtocolUnitTests(unittest.TestCase):
    def test_net_2g(self):
        net = protocol.parse_net("NET 3 -55 12 WPA2 BE:41:99:0B:20:36 home-ap")
        self.assertEqual(net["index"], 3)
        self.assertEqual(net["channel"], 12)
        self.assertEqual(net["rssi"], -55)
        self.assertEqual(net["bssid"], "BE:41:99:0B:20:36")
        self.assertEqual(net["ssid"], "home-ap")
        self.assertEqual(net["band"], "2.4G")

    def test_net_5g(self):
        net = protocol.parse_net("NET 0 -40 48 WPA2 F2:5C:81:E7:0A:19 big-drone")
        self.assertEqual(net["band"], "5G")

    def test_net_ssid_with_spaces(self):
        net = protocol.parse_net("NET 1 -70 6 WPA/WPA2 00:11:22:33:44:55 my home  wifi")
        self.assertEqual(net["ssid"], "my home  wifi")

    def test_net_hidden_ssid(self):
        net = protocol.parse_net("NET 2 -80 1 WPA2 00:11:22:33:44:55 ")
        self.assertEqual(net["ssid"], "")

    def test_net_malformed(self):
        self.assertIsNone(protocol.parse_net("NET x y z w"))
        self.assertIsNone(protocol.parse_net("SCAN_BEGIN"))

    def test_status_parsing(self):
        info = protocol.parse_status(
            "STATUS mode=single eliminated=7 networks=93 creds=0 heap=61234 caps=deauth,eviltwin,5g"
        )
        self.assertEqual(info["mode"], "single")
        self.assertEqual(info["eliminated"], "7")
        self.assertEqual(info["heap"], "61234")
        self.assertEqual(protocol.parse_caps(info), {"deauth", "eviltwin", "5g"})
        self.assertTrue(protocol.mode_is_attacking(info["mode"]))
        self.assertFalse(protocol.mode_is_attacking("idle"))

    def test_status_without_caps(self):
        info = protocol.parse_status("STATUS mode=idle eliminated=0")
        self.assertEqual(protocol.parse_caps(info), set())

    def test_classify(self):
        cases = {
            "SCAN_BEGIN": "scan_begin",
            "SCAN_END 17": "scan_end",
            "OK PONG": "ok",
            "ERR line too long": "err",
            "INFO Wireless-Attack ready, type HELP": "info",
            "CREDS_BEGIN": "creds_begin",
            "CREDS_END 0": "creds_end",
            "NET 0 -40 48 WPA2 aa:bb:cc:dd:ee:ff x": "net",
            "STATUS mode=idle": "status",
            "something odd": "raw",
            "": "empty",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(protocol.classify(line)[0], expected)

    def test_cred(self):
        cred = protocol.parse_cred("CRED 0 alice hunter2 12345")
        self.assertEqual(cred["username"], "alice")
        self.assertEqual(cred["password"], "hunter2")

    def test_band_boundaries(self):
        self.assertEqual(protocol.band_of_channel(14), "2.4G")
        self.assertEqual(protocol.band_of_channel(15), "5G")
        self.assertEqual(protocol.band_of_channel("36"), "5G")
        self.assertEqual(protocol.band_of_channel("x"), "?")


# ------------------------------------------------------------------------ hardware


class SerialClient:
    def __init__(self, port):
        import serial

        self.ser = serial.Serial(port, 115200, timeout=0.2, dsrdtr=False, rtscts=False)
        self.ser.dtr = False
        self.ser.rts = False

    def send(self, command):
        self.ser.write((command + "\r\n").encode())

    def read_until(self, predicate, timeout=8.0):
        deadline = time.time() + timeout
        lines = []
        while time.time() < deadline:
            raw = self.ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            lines.append(line)
            if predicate(line):
                return line, lines
        return None, lines

    def command(self, command, predicate, timeout=8.0):
        self.send(command)
        return self.read_until(predicate, timeout)

    def drain(self, seconds=0.3):
        deadline = time.time() + seconds
        while time.time() < deadline:
            self.ser.readline()

    def sync(self, timeout=12.0):
        """Wait until the firmware answers a PING (the board may still be booting)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.ser.reset_input_buffer()
            self.send("PING")
            line, _ = self.read_until(lambda l: l.startswith("OK PONG"), 1.0)
            if line is not None:
                return True
        return False

    def close(self):
        self.ser.close()


def _open_client():
    try:
        return SerialClient(PORT)
    except Exception as exc:  # noqa: BLE001
        raise unittest.SkipTest(f"{PORT} 打不开: {exc}")


class FirmwareFunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _open_client()
        if not cls.client.sync():
            cls.client.close()
            raise unittest.SkipTest(f"{PORT} 打开但没有响应（固件未就绪）")
        cls.client.drain(0.3)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "client", None):
            cls.client.close()

    def test_ping(self):
        line, _ = self.client.command("PING", lambda l: l.startswith("OK PONG"), 3)
        self.assertIsNotNone(line, "PING 无响应")

    def test_help_lists_commands(self):
        _, lines = self.client.command("HELP", lambda l: "CREDS" in l, 3)
        text = "\n".join(lines)
        for cmd in ("SCAN", "DEAUTH", "STOP", "EVILTWIN", "CREDS"):
            self.assertIn(cmd, text)

    def test_status_fields(self):
        line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 3)
        self.assertIsNotNone(line)
        info = protocol.parse_status(line)
        for key in ("mode", "eliminated", "networks", "heap", "caps"):
            self.assertIn(key, info, f"STATUS 缺少 {key}")
        self.assertIn("deauth", protocol.parse_caps(info))
        self.assertGreater(int(info["heap"]), 10000, "空闲堆过小")

    def test_scan_returns_networks(self):
        self.client.send("SCAN")
        line, lines = self.client.read_until(lambda l: l.startswith("SCAN_END"), 25)
        self.assertIsNotNone(line, "SCAN 超时")
        nets = [l for l in lines if l.startswith("NET ")]
        count = int(line.split(" ")[-1])
        self.assertEqual(len(nets), count, "NET 行数与 SCAN_END 不一致")
        self.assertGreater(count, 0, "一个网络都没扫到")
        for net_line in nets:
            self.assertIsNotNone(protocol.parse_net(net_line), f"NET 行无法解析: {net_line}")

    def test_deauth_out_of_range(self):
        self.client.command("SCAN", lambda l: l.startswith("SCAN_END"), 25)
        line, _ = self.client.command("DEAUTH 9999 1", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line, "越界索引未报错")

    def test_unknown_command(self):
        line, _ = self.client.command("FOO", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line)
        self.assertIn("unknown command", line)

    def test_stop_when_idle(self):
        line, _ = self.client.command("STOP", lambda l: l.startswith("OK STOP"), 3)
        self.assertIsNotNone(line)
        line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 3)
        self.assertIn("mode=idle", line)

    def test_evil_twin_requires_scan(self):
        self.client.command("SCAN", lambda l: l.startswith("SCAN_END"), 25)
        line, _ = self.client.command("EVILTWIN 9999", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line, "EVILTWIN 越界未报错（不应真的开热点）")

    def test_creds_empty(self):
        _, lines = self.client.command("CREDS", lambda l: l.startswith("CREDS_END"), 3)
        self.assertTrue(any(l.startswith("CREDS_BEGIN") for l in lines))

    def test_stats_format(self):
        _, lines = self.client.command("STATS", lambda l: l.startswith("STATS_END"), 5)
        self.assertTrue(any(l.startswith("STATS_BEGIN") for l in lines))
        begin = next(l for l in lines if l.startswith("STATS_BEGIN"))
        for key in ("mode=", "deauth_frames=", "probe_frames=", "aps="):
            self.assertIn(key, begin, f"STATS_BEGIN 缺少 {key}")
        for line in lines:
            if line.startswith("AP "):
                parts = line.split(" ")
                self.assertEqual(len(parts), 5, f"AP 行格式不对: {line}")
                self.assertIn("frames=", parts[4])

    def test_reason_validation_and_random(self):
        """reason 防呆：0 / 越界 / 非数字要报错；random 模式要能在 STATUS 里看到。"""
        ok, _ = self.client.command("REASON 7", lambda l: l.startswith("OK REASON 7"), 3)
        self.assertIsNotNone(ok, "合法 reason 应被接受")
        for bad in ("0", "65536", "-1", "abc", "7x"):
            line, _ = self.client.command(f"REASON {bad}",
                                          lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"reason {bad} 应报错")
            self.assertIn("1..65535", line)

        line, _ = self.client.command("REASON random", lambda l: l.startswith("OK REASON"), 3)
        self.assertIsNotNone(line, "random 模式应被接受")
        status, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 5)
        info = protocol.parse_status(status)
        self.assertEqual(info.get("reason"), "random", "STATUS 应显示 reason=random")

        # 不在标准定义集合里的值可以用，但要给出提示
        line, _ = self.client.command("REASON 99", lambda l: l.startswith("OK REASON"), 3)
        self.assertIsNotNone(line)

        # 复位成默认值，避免影响其它用例
        self.client.command("REASON 1", lambda l: l.startswith("OK REASON"), 3)

    def test_deauth_only_requires_list(self):
        line, _ = self.client.command("DEAUTH_ONLY", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line, "无参数的 DEAUTH_ONLY 应报错")

    def test_deauth_only_rejects_garbage(self):
        line, _ = self.client.command("DEAUTH_ONLY x,y 1", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line, "非法序号列表应报错")

    def test_deauth_frames_go_out(self):
        """攻击真的在发帧：txok 增长、driver 没有整片拒收、广播兜底生效。

        这一条是为了守住"deauth_frames 在涨但帧没出去"的那个 bug——
        之前注入在混杂回调里连发 16 帧，2/3 的调用返回 ESP_ERR_NO_MEM 却被忽略。
        """
        self.client.send("SCAN")
        line, _ = self.client.read_until(lambda l: l.startswith("SCAN_END"), 40)
        self.assertIsNotNone(line, "扫描超时")

        line, _ = self.client.command("DEAUTH_ALL 7", lambda l: l.startswith("OK DEAUTH_ALL"), 5)
        self.assertIsNotNone(line, "DEAUTH_ALL 无响应")
        time.sleep(4.0)
        line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 5)
        self.client.command("STOP", lambda l: l.startswith("OK STOP"), 5)
        self.assertIsNotNone(line)

        info = protocol.parse_status(line)
        txok = int(info.get("txok", "0"))
        txerr = int(info.get("txerr", "0"))
        blind = int(info.get("blind", "0"))
        frames = int(info.get("deauth_frames", "0"))
        print(f"\n  deauth_frames={frames} txok={txok} txerr={txerr} blind={blind}")
        self.assertGreater(txok, 0, "没有任何一帧被驱动接受（注入路径断了）")
        self.assertEqual(frames, txok, "deauth_frames 应等于真正被接受的帧数")
        self.assertGreater(blind, 0, "广播兜底没生效（blind 应为非零）")
        # 帧在被接受之前可以重试，但失败重试不该比成功次数高一个量级
        self.assertLess(txerr, txok * 3 + 50, "注入失败率过高，检查退避/束大小")

    def test_probe_broadcast_counters(self):
        self.client.command("STOP", lambda l: l.startswith("OK STOP"), 3)
        line, _ = self.client.command("PROBE_BROADCAST", lambda l: l.startswith("OK PROBE_BROADCAST"), 3)
        self.assertIsNotNone(line)
        time.sleep(1.5)
        line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 3)
        info = protocol.parse_status(line)
        self.assertEqual(info["mode"], "probe-bcast")
        self.assertGreater(int(info["probe_frames"]), 100, "Probe 帧数没有增长")
        print(f"probe_frames={info['probe_frames']}")
        self.client.command("STOP", lambda l: l.startswith("OK STOP"), 3)

    def test_stations_window(self):
        self.client.command("STOP", lambda l: l.startswith("OK STOP"), 3)
        line, _ = self.client.command("STATIONS 3", lambda l: l.startswith("OK STATIONS"), 3)
        self.assertIsNotNone(line)
        line, lines = self.client.read_until(lambda l: l.startswith("STA_END"), 12)
        self.assertIsNotNone(line, "STATIONS 未在窗口内结束")
        self.assertTrue(any(l == "STA_BEGIN" for l in lines))

    def test_line_too_long(self):
        self.client.send("X" * 200)
        line, _ = self.client.read_until(lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line)
        self.assertIn("line too long", line)
        line, _ = self.client.command("PING", lambda l: l.startswith("OK PONG"), 3)
        self.assertIsNotNone(line, "超长行之后固件失联")

    def test_crlf_and_empty_lines(self):
        self.client.send("")
        self.client.send("   ")
        line, _ = self.client.command("PING", lambda l: l.startswith("OK PONG"), 3)
        self.assertIsNotNone(line, "空行之后固件失联")


class FirmwareStabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _open_client()
        if not cls.client.sync():
            cls.client.close()
            raise unittest.SkipTest(f"{PORT} 打开但没有响应（固件未就绪）")
        cls.client.drain(0.3)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "client", None):
            cls.client.close()

    def test_heap_stable_over_cycles(self):
        heaps = []
        for _ in range(60):
            line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 3)
            self.assertIsNotNone(line, "STATUS 超时")
            heaps.append(int(protocol.parse_status(line)["heap"]))
        first, last = heaps[0], heaps[-1]
        spread = max(heaps) - min(heaps)
        print(f"\n  堆内存: first={first} last={last} spread={spread}")
        self.assertGreater(last, 10000)
        self.assertLess(last, first + 4096, "堆内存持续上涨（疑似泄漏）")
        self.assertLess(spread, 32768, "堆波动过大")

    def test_repeated_scans(self):
        counts = []
        for _ in range(4):
            self.client.send("SCAN")
            line, lines = self.client.read_until(lambda l: l.startswith("SCAN_END"), 25)
            self.assertIsNotNone(line, "连续扫描超时")
            counts.append(len([l for l in lines if l.startswith("NET ")]))
        print(f"\n  连续扫描网络数: {counts}")
        self.assertTrue(all(c > 0 for c in counts))

    def test_idle_keeps_responding(self):
        time.sleep(5)
        line, _ = self.client.command("PING", lambda l: l.startswith("OK PONG"), 3)
        self.assertIsNotNone(line, "空闲 5 秒后无响应")


class FirmwareStressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _open_client()
        if not cls.client.sync():
            cls.client.close()
            raise unittest.SkipTest(f"{PORT} 打开但没有响应（固件未就绪）")
        cls.client.drain(0.3)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "client", None):
            cls.client.close()

    def test_command_flood(self):
        total = 300
        for _ in range(total):
            self.client.send("PING")
        pongs = 0
        deadline = time.time() + 20
        while time.time() < deadline and pongs < total:
            raw = self.client.ser.readline()
            if raw and raw.startswith(b"OK PONG"):
                pongs += 1
        print(f"\n  连发 {total} 条 PING, 收到 {pongs} 条响应")
        # With the 4 KB UART RX ring all 300 lines must survive; anything below 95%
        # means the ring is too small again (or the parser dropped a line).
        self.assertGreaterEqual(pongs, int(total * 0.95), "指令风暴丢行过多（检查 RX 环形缓冲）")
        line, _ = self.client.command("PING", lambda l: l.startswith("OK PONG"), 5)
        self.assertIsNotNone(line, "指令风暴后固件失联")

    def test_garbage_bytes(self):
        self.client.ser.write(bytes(range(1, 32)))
        self.client.ser.write(b"\r\n")
        self.client.drain(0.5)
        line, _ = self.client.command("PING", lambda l: l.startswith("OK PONG"), 5)
        self.assertIsNotNone(line, "垃圾字节后固件失联")


class FirmwarePerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = _open_client()
        if not cls.client.sync():
            cls.client.close()
            raise unittest.SkipTest(f"{PORT} 打开但没有响应（固件未就绪）")
        cls.client.drain(0.3)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "client", None):
            cls.client.close()

    def _rtt(self, command, predicate):
        start = time.perf_counter()
        line, _ = self.client.command(command, predicate, 5)
        self.assertIsNotNone(line, f"{command} 超时")
        return (time.perf_counter() - start) * 1000.0

    def test_ping_latency(self):
        samples = [self._rtt("PING", lambda l: l.startswith("OK PONG")) for _ in range(50)]
        p50 = statistics.median(samples)
        p95 = sorted(samples)[int(len(samples) * 0.95) - 1]
        print(f"\n  PING 往返: p50={p50:.1f}ms p95={p95:.1f}ms max={max(samples):.1f}ms")
        self.assertLess(p50, 60, "PING 延迟过大")

    def test_status_latency(self):
        samples = [self._rtt("STATUS", lambda l: l.startswith("STATUS ")) for _ in range(20)]
        p50 = statistics.median(samples)
        print(f"\n  STATUS 往返: p50={p50:.1f}ms")
        self.assertLess(p50, 60)

    def test_scan_duration(self):
        start = time.perf_counter()
        self.client.send("SCAN")
        line, _ = self.client.read_until(lambda l: l.startswith("SCAN_END"), 40)
        elapsed = time.perf_counter() - start
        self.assertIsNotNone(line, "扫描超时")
        print(f"\n  单次扫描耗时: {elapsed:.2f}s")
        self.assertLess(elapsed, 20, "扫描过慢")


class LvglUiTests(unittest.TestCase):
    """LVGL 触摸界面：就绪标志 + 启用后的内存余量 + 目标选择弹窗。"""

    def test_ui_ready_and_heap(self):
        client = _open_client()
        try:
            if not client.sync():
                raise unittest.SkipTest("固件无响应")
            line, _ = client.command("STATUS", lambda l: l.startswith("STATUS "), 5)
            self.assertIsNotNone(line)
            info = protocol.parse_status(line)
            ui = info.get("ui", "0")
            heap = int(info.get("heap", "0"))
            print(f"ui={ui} heap={heap}")
            self.assertEqual(ui, "1", "该固件未启用 LVGL（STATUS ui=0）")
            self.assertGreater(heap, 20000, "启用 LVGL 后空闲堆过低")
        finally:
            client.close()

    def test_target_popup(self):
        """扫描后打开屏上的目标选择弹窗：行数 = min(网络数, 30)，且不泄漏堆。"""
        client = _open_client()
        try:
            if not client.sync():
                raise unittest.SkipTest("固件无响应")
            client.send("SCAN")
            line, _ = client.read_until(lambda l: l.startswith("SCAN_END"), 40)
            self.assertIsNotNone(line, "扫描超时")

            def parse_ui(text):
                fields = {}
                for token in text.split(" ")[1:]:
                    if "=" in token:
                        key, value = token.split("=", 1)
                        fields[key] = value
                return fields

            line, _ = client.command("UI", lambda l: l.startswith("UI "), 5)
            self.assertIsNotNone(line, "UI 无响应")
            before = parse_ui(line)
            self.assertEqual(before.get("popup"), "0", "弹窗不该自己弹出来")

            heap_before = int(
                protocol.parse_status(
                    client.command("STATUS", lambda l: l.startswith("STATUS "), 5)[0]
                ).get("heap", "0")
            )

            # 连开多次，确认重建列表不泄漏
            for _ in range(3):
                ok, _ = client.command("UITARGETS", lambda l: l.startswith("OK UITARGETS"), 5)
                self.assertIsNotNone(ok, "UITARGETS 无响应")
            line, _ = client.command("UI", lambda l: l.startswith("UI "), 5)
            after = parse_ui(line)
            nets = int(after.get("nets", "0"))
            items = int(after.get("items", "0"))
            print(f"popup={after.get('popup')} items={items} nets={nets}")
            self.assertEqual(after.get("popup"), "1", "UITARGETS 之后弹窗应为可见")
            self.assertEqual(items, min(nets, 30), "弹窗行数应等于 min(网络数, LIST_ROWS)")

            heap_after = int(
                protocol.parse_status(
                    client.command("STATUS", lambda l: l.startswith("STATUS "), 5)[0]
                ).get("heap", "0")
            )
            print(f"heap {heap_before} -> {heap_after}")
            self.assertLess(heap_before - heap_after, 8192, "反复开弹窗后堆下降过多（疑似泄漏）")
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
