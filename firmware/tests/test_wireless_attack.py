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

    def setUp(self):
        # 每条用例前把上一条可能留下的攻击/CSA 循环清掉：CSA 自动模式会一直
        # 循环并停在 5G 信道上，残留状态会让后面的扫描/攻击用例偶发失败。
        self.client.command("STOP", lambda l: l.startswith("OK"), 3)
        self.client.command("CSASTOP", lambda l: l.startswith("OK CSASTOP"), 3)
        self.client.command("DELBASTOP", lambda l: l.startswith("OK DELBASTOP"), 3)
        self.client.command("BASTOP", lambda l: l.startswith("OK BASTOP"), 3)
        self.client.drain(0.2)

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

    def test_csa_frame_format_and_run(self):
        """CSA：帧格式（Action cat=4 act=4 / Beacon IE 37）+ 参数校验 + 真的开始跑。"""
        self.client.send("CSATEST")
        line, lines = self.client.read_until(
            lambda l: l.startswith("CSATEST beacon hex="), 6)
        self.assertIsNotNone(line, "CSATEST 无输出")
        text = "\n".join(lines)
        self.assertIn("cat=4 act=4", text, "Action 帧应为 category 4 / action 4")
        self.assertIn("id=37 ie_len=3", text, "Beacon 里应有 CSA IE (id 37, len 3)")

        # 参数防呆：信道 0 / 越界信道 / count 越界 / 序号越界 都要报错
        for bad in ("CSA 0 0", "CSA 0 200", "CSA 0 6 9", "CSA 99 6"):
            line, _ = self.client.command(bad, lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"{bad} 应被拒绝")

        # 真的跑：扫一次，挑和 AP 不同的信道
        self.client.send("SCAN")
        line, lines = self.client.read_until(lambda l: l.startswith("SCAN_END"), 40)
        self.assertIsNotNone(line, "扫描超时")
        ap_ch = None
        for l in lines:
            if l.startswith("NET 0 "):
                ap_ch = int(l.split(" ")[3])
        self.assertIsNotNone(ap_ch, "没有解析到 NET 0")
        new_ch = 1 if ap_ch != 1 else 6
        ok, _ = self.client.command(f"CSA 0 {new_ch} 5 3", lambda l: l.startswith("OK CSA"), 5)
        self.assertIsNotNone(ok, "CSA 启动失败")
        time.sleep(1.5)
        line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 5)
        info = protocol.parse_status(line)
        print(f"\n  csa={info.get('csa')} csaf={info.get('csaf')} csac={info.get('csac')}")
        self.assertIn(info.get("csa"), ("announce", "hold"), "STATUS 应显示 CSA 阶段")
        self.assertGreater(int(info.get("csaf", "0")), 0, "CSA 帧数应大于 0")
        stop, _ = self.client.command("CSASTOP", lambda l: l.startswith("OK CSASTOP"), 5)
        self.assertIsNotNone(stop)

        # 自动模式：不指定信道 -> 对向频段随机信道 + 循环
        ok, _ = self.client.command("CSA 0", lambda l: l.startswith("OK CSA"), 5)
        self.assertIsNotNone(ok, "CSA 自动模式启动失败")
        self.assertIn("auto", ok, "自动模式应在 OK 行里标出来")
        time.sleep(6.0)  # 5 轮播报（约 0.5s）+ hold 5s，确保至少走完一轮
        line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 5)
        info = protocol.parse_status(line)
        print(f"\n  auto: csa={info.get('csa')} csaauto={info.get('csaauto')} "
              f"csch={info.get('csch')} cycles={info.get('csacycle')}")
        self.assertEqual(info.get("csaauto"), "1", "自动模式应标记 csaauto=1")
        self.assertGreaterEqual(int(info.get("csacycle", "0")), 1, "应至少完成一轮")
        ch = int(info.get("csch", "0"))
        if ap_ch <= 14:
            self.assertGreaterEqual(ch, 36, "2.4G 的 AP 应被通告到 5G 信道")
        else:
            self.assertLessEqual(ch, 14, "5G 的 AP 应被通告到 2.4G 信道")
        self.client.command("CSASTOP", lambda l: l.startswith("OK CSASTOP"), 5)

    def test_delba_frame_format_and_run(self):
        """DELBA：帧格式（Action cat=3 act=2 / TID 与 Initiator 位）+ 参数防呆 + 真的开始跑。

        帧结构按 802.11-2020：24 字节头 + Category(3) + Action(2) + DELBA 参数集 +
        reason；参数集 bit11 = Initiator、bit12-15 = TID。单播方向的 Addr2 必须是
        目标 AP 的 BSSID，否则客户端按 DA/SA 找不到会话直接丢帧。
        """
        self.client.send("DELBATEST")
        line, _ = self.client.command("", lambda l: l.startswith("DELBATEST ap_to_sta"), 6)
        self.assertIsNotNone(line, "DELBATEST 无输出")
        self.assertIn("len=30", line, "DELBA 帧应为 30 字节")
        self.assertIn("cat=3", line, "Category 必须是 3 (Block Ack)")
        self.assertIn("act=2", line, "Action 必须是 2 (DELBA)")
        self.assertIn("init=1", line, "Initiator 位（bit11）必须置 1")
        self.assertIn("hex=", line)
        hexpart = line.split("hex=")[1]
        self.assertTrue(hexpart.startswith("D000"), "管理帧 subtype 13 的 FC 是 D0 00")

        # TID 编码：tid=3 时参数集高字节低半字节应为 3（bit12 起）
        self.client.send("DELBATEST")
        lines = []
        deadline = time.time() + 6
        while time.time() < deadline:
            raw = self.client.ser.readline()
            if not raw:
                continue
            text = raw.decode("utf-8", "replace").rstrip()
            lines.append(text)
            if "tid=3" in text:
                break
        tid3 = [l for l in lines if "tid=3" in l]
        self.assertTrue(tid3, "DELBATEST 应覆盖 tid=3")
        body = tid3[0].split("hex=")[1]
        params_high = int(body[54:56], 16)  # frame[27]：bit12-15 = TID
        self.assertEqual(params_high & 0xF0, 0x30, "TID 应编码在 bit12-15")

        # reason 防呆：只接受真实对端会用到的 1/32/37/38/39
        for bad in ("0", "7", "65535", "abc"):
            line, _ = self.client.command(f"DELBA 0 {bad}", lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"DELBA reason={bad} 应被拒绝")

        # 无扫描结果时不能启动
        line, _ = self.client.command("DELBA 99 37", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line, "越界序号应报错")

        # 真跑：扫描后对第一个 AP 发 DELBA，帧数要涨
        self.client.send("SCAN")
        line, _ = self.client.command("", lambda l: l.startswith("SCAN_END"), 40)
        self.assertIsNotNone(line, "扫描超时")
        ok, _ = self.client.command("DELBA 0 37", lambda l: l.startswith("OK DELBA"), 5)
        self.assertIsNotNone(ok, "DELBA 启动失败")
        time.sleep(2.0)
        status, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 5)
        info = protocol.parse_status(status)
        print(f"\n  delba={info.get('delba')} frames={info.get('delbaf')} "
              f"clients={info.get('delbac')} tids={info.get('delbat')}")
        self.assertEqual(info.get("delba"), "on", "STATUS 应显示 delba=on")
        self.assertGreater(int(info.get("delbaf", "0")), 0, "DELBA 帧数应大于 0")
        stop, _ = self.client.command("DELBASTOP", lambda l: l.startswith("OK DELBASTOP"), 5)
        self.assertIsNotNone(stop)
        info = protocol.parse_status(
            self.client.command("STATUS", lambda l: l.startswith("STATUS "), 5)[0])
        self.assertEqual(info.get("delba"), "off", "STOP 后应回到 off")

    def test_ba_attack_frames_and_guards(self):
        """BA 会话劫持：ADDBA Request / BAR 的字节布局 + 参数防呆 + 驱动接受。

        ADDBA Request = 24 + cat + action + dialog + 参数集 + timeout + SSN(<<4) = 33 B；
        BAR（压缩）= RA/TA + BAR control + BAR info(SSN<<4) = 20 B。
        `step` 越界要被拒绝；`BATX` 里三种帧都要被驱动接受（返回 0）。
        """
        self.client.send("BATEST")
        line, _ = self.client.command("", lambda l: l.startswith("BATEST addba"), 6)
        self.assertIsNotNone(line, "BATEST 无输出")
        self.assertIn("len=33", line)
        self.assertIn("cat=3", line)
        self.assertIn("act=0", line)
        self.assertIn("tid=5", line)
        self.assertIn("ssn=1175", line)
        body = line.split("hex=")[1]
        # SSN<<4 = 1175<<4 = 0x4970，在帧尾两字节（小端 70 49）
        self.assertTrue(body.endswith("7049"), "SSN 应编码在帧尾（<<4, little endian）")

        self.client.send("BATEST")
        bar, _ = self.client.command("", lambda l: l.startswith("BATEST bar"), 6)
        self.assertIsNotNone(bar, "BATEST 缺少 BAR 行")
        self.assertIn("len=20", bar)
        self.assertIn("subtype=8", bar)
        self.assertIn("compressed=1", bar)
        self.assertIn("tid=5", bar)
        self.assertTrue(bar.split("hex=")[1].startswith("8400"), "控制帧 subtype 8 的 FC 是 84 00")

        # 驱动必须接受这三种帧，否则整个攻击只是空转
        tx, _ = self.client.command("BATX", lambda l: l.startswith("BATX"), 5)
        self.assertIsNotNone(tx)
        self.assertIn("delba(30B)=0", tx)
        self.assertIn("addba(33B)=0", tx)
        self.assertIn("bar(20B)=0", tx)

        # 参数防呆
        for bad in ("2048", "-1", "99999"):
            line, _ = self.client.command(f"BAATTACK 0 {bad}", lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"step={bad} 应被拒绝")
        line, _ = self.client.command("BAATTACK 99 512", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line, "越界序号应报错")
        line, _ = self.client.command("BAPLANT 99", lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(line, "BAPLANT 越界序号应报错")

    def test_ui_screens_switch(self):
        """LVGL：每个屏幕都能构建出来（切屏后不崩、堆不塌），含五个新模块页。"""
        for name in ("menu", "deauth", "mode", "probe", "csa", "delba", "ba", "evil",
                     "wnm", "tim", "eapol", "sae", "authflood"):
            line, _ = self.client.command(f"UISCREEN {name}",
                                          lambda l: l.startswith(("OK UISCREEN", "ERR ")), 5)
            self.assertIsNotNone(line, f"UISCREEN {name} 无响应")
            if line.startswith("ERR "):
                # 没有 LVGL 的构建（例如 C5）上这条要优雅地报错，不能挂
                self.assertIn("LVGL", line)
                return
            self.assertIn(name, line)

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
        rev = int(info.get("rev", "0"))
        frames = int(info.get("deauth_frames", "0"))
        print(f"\n  deauth_frames={frames} txok={txok} txerr={txerr} blind={blind} rev={rev}")
        self.assertGreater(txok, 0, "没有任何一帧被驱动接受（注入路径断了）")
        self.assertEqual(frames, txok, "deauth_frames 应等于真正被接受的帧数")
        self.assertGreater(blind, 0, "广播兜底没生效（blind 应为非零）")
        # rev 只在嗅到客户端时才增长（11n 射频解不出 HE 客户端时它恒为 0），
        # 所以它是观察项而不是判据：判据是 txok/blind。
        if rev == 0:
            print("  rev=0（本轮没有嗅到可解码的客户端，属已知环境限制）")
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

    # ---- wbus：已迁移到总线的命令（TODO.md 第 5 节 P1）----------------------

    def test_wbus_lists_migrated_objects(self):
        line, lines = self.client.command("WBUS", lambda l: l.startswith("WBUS csa"), 3)
        self.assertIsNotNone(line, "WBUS 未列出 csa")
        text = "\n".join(lines)
        self.assertIn("WBUS objects=2", text)
        self.assertIn("WBUS deauth", text)
        self.assertIn("methods=start,stop", text)
        self.assertIn("events=state", text)

    def test_describe_reports_arguments(self):
        line, lines = self.client.command("DESCRIBE csa", lambda l: l.startswith("EVT "), 3)
        self.assertIsNotNone(line, "DESCRIBE csa 没有输出 EVT 行")
        text = "\n".join(lines)
        self.assertIn('OBJ csa "CSA spoof"', text)
        self.assertIn("METHOD csa.start", text)
        self.assertIn("ARG csa.start ch type=enum default=-1 values=auto", text)
        self.assertIn("ARG csa.start secs type=int default=15", text)
        self.assertIn("METHOD csa.test", text)

    def test_call_matches_legacy_aliases(self):
        self.client.command("SCAN", lambda l: l.startswith("SCAN_END"), 25)
        line, _ = self.client.command("CALL deauth.start idx=9999", lambda l: l.startswith("ERR "), 3)
        self.assertEqual(line, "ERR index out of range, run SCAN first")
        line, _ = self.client.command("CALL deauth.start idx=0 reason=0",
                                      lambda l: l.startswith("ERR "), 3)
        self.assertEqual(line, "ERR reason must be 1..65535, or 'random'")
        line, _ = self.client.command("CALL deauth.start nope=1", lambda l: l.startswith("ERR "), 3)
        self.assertIn("unknown arg nope", line)
        line, _ = self.client.command("CALL nosuch.start idx=0", lambda l: l.startswith("ERR "), 3)
        self.assertIn("unknown object nosuch", line)
        line, _ = self.client.command("CALL csa.start idx=0 ch=999", lambda l: l.startswith("ERR "), 3)
        self.assertEqual(line, "ERR new channel must be 1..14 or 36..196")

    def test_legacy_leniency_survives_the_migration(self):
        # 迁移前就接受（且不报错）的写法，迁移后必须继续接受，否则脚本会断。
        self.client.command("SCAN", lambda l: l.startswith("SCAN_END"), 25)
        line, _ = self.client.command("CSA 0 auto 99", lambda l: l.startswith("OK CSA"), 3)
        self.assertIsNotNone(line, "auto 模式仍应忽略 count 参数")
        self.assertIn("count=5", line)
        self.client.command("CSASTOP", lambda l: l.startswith("OK CSASTOP"), 3)
        line, _ = self.client.command("DEAUTH 9999x", lambda l: l.startswith("ERR "), 3)
        self.assertEqual(line, "ERR index out of range, run SCAN first")

    def test_events_are_opt_in(self):
        self.client.command("SCAN", lambda l: l.startswith("SCAN_END"), 25)
        line, _ = self.client.command("EVTSUB deauth.*", lambda l: l.startswith("OK EVTSUB"), 3)
        self.assertIsNotNone(line, "EVTSUB 未确认")
        self.client.send("DEAUTH 0")
        line, _ = self.client.read_until(lambda l: l.startswith("EVT "), 4)
        self.assertEqual(line, "EVT deauth.state active=1")
        self.client.command("STOP", lambda l: l.startswith("OK STOP"), 3)
        line, _ = self.client.command("EVTSUB", lambda l: l.startswith("OK EVTSUB none"), 3)
        self.assertIsNotNone(line, "EVTSUB 关闭未确认")
        self.client.send("DEAUTH 0")
        _, lines = self.client.read_until(lambda l: l.startswith("OK DEAUTH"), 4)
        self.client.command("STOP", lambda l: l.startswith("OK STOP"), 3)
        self.assertFalse([l for l in lines if l.startswith("EVT ")], "取消订阅后仍在发事件")


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
        # 这一条测的是串口时间而不是固件速度：STATUS 一行在 115200 下约 1.1 KB
        # （五个新模块各带一组计数器），按 11.5 KB/s 算就是 ~95 ms。旧阈值 60 ms 是
        # 按当年 ~700 字节的行标的，行变长后同步放宽到 120 ms。
        self.assertLess(p50, 120)

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

    def test_reason_popup(self):
        """屏上的 reason 弹窗：每个标准 reason 一行 + random，共 24 行。"""
        client = _open_client()
        try:
            if not client.sync():
                raise unittest.SkipTest("固件无响应")

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
            self.assertEqual(before.get("rpopup"), "0", "reason 弹窗不该自己弹出来")
            self.assertEqual(int(before.get("ritems", "0")), 24, "应为 23 个标准 reason + random")

            ok, _ = client.command("UIREASON", lambda l: l.startswith("OK UIREASON"), 5)
            self.assertIsNotNone(ok, "UIREASON 无响应")
            line, _ = client.command("UI", lambda l: l.startswith("UI "), 5)
            after = parse_ui(line)
            print("  reason popup rpopup=" + str(after.get("rpopup")) +
                  " ritems=" + str(after.get("ritems")))
            self.assertEqual(after.get("rpopup"), "1", "UIREASON 之后弹窗应可见")
        finally:
            client.close()


class FirmwareControlFrameModuleTests(unittest.TestCase):
    """802.11v / TIM / EAPOL / SAE / Auth 洪泛这五个模块的帧格式与运行检查。

    这些用例都不打真实客户端：WNM 与 EAPOL 用 `02AA...` 这个假 STA MAC 把自己当目标，
    其余三个模块本来就朝 BSSID/广播发。判据是"字节对不对 + 计数器动了"，
    空口上的确认见 lab/cap_frames.py（C5 抓包管道）。
    """

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

    def setUp(self):
        self.client.command("STOP", lambda l: l.startswith("OK STOP"), 3)
        self.client.drain(0.2)

    def _scan_first_ap(self):
        self.client.send("SCAN")
        line, lines = self.client.read_until(lambda l: l.startswith("SCAN_END"), 40)
        self.assertIsNotNone(line, "扫描超时")
        for l in lines:
            if l.startswith("NET 0 "):
                return int(l.split(" ")[3])
        self.skipTest("没有扫描到 AP")

    def _status(self):
        line, _ = self.client.command("STATUS", lambda l: l.startswith("STATUS "), 5)
        self.assertIsNotNone(line, "STATUS 无响应")
        return protocol.parse_status(line)

    def test_help_lists_new_commands(self):
        _, lines = self.client.command("HELP", lambda l: "AUTHFLOODTEST" in l, 5)
        text = "\n".join(lines)
        for cmd in ("WNM ", "TIM ", "EAPOL ", "SAE ", "AUTHFLOOD ", "WNMTEST",
                    "PSPOLL ", "PSPOLLREL ", "PSPOLLTEST"):
            self.assertIn(cmd, text, f"HELP 应列出 {cmd}")

    def test_status_has_new_fields(self):
        info = self._status()
        for key in ("wnm", "wnmf", "wnmskip", "wnmresp", "tim", "timf", "timaid", "timreal",
                    "eap", "eapf", "eaprxreq", "sae", "saesec", "saef", "saecode", "saetok",
                    "af", "aff", "afa", "afs", "afids", "afst", "afup",
                    "psp", "pspf", "pspnul", "pspfl", "pspc", "pspdl", "psprxp"):
            self.assertIn(key, info, f"STATUS 缺少 {key}")
        self.assertIn("authflood", protocol.parse_caps(info))

    def test_wnm_frame_format_and_run(self):
        """BTM Request：category 10 / action 7、Disassociation Imminent、候选 Neighbor Report。"""
        self.client.send("WNMTEST")
        line, lines = self.client.command("", lambda l: l.startswith("WNMTEST hex="), 6)
        self.assertIsNotNone(line, "WNMTEST 无输出")
        text = "\n".join(lines)
        self.assertIn("cat=10 act=7", text, "应为 WNM Action (category 10, action 7)")
        self.assertIn("imm=1", text, "必须置 Disassociation Imminent")
        self.assertIn("cand=1", text, "cand 模式必须带候选列表")
        self.assertIn("timer=10", text, "disassociation timer 必须非 0（客户端才会扫）")
        self.assertIn("eid=52 ie_len=13", text, "候选 BSS 是 Neighbor Report 元素 (52/13)")

        # 参数防呆：mode 拼错、timer 0、信道越界
        for bad in ("WNM 0 nope", "WNM 0 cand 0", "WNM 0 cand 10 999"):
            line, _ = self.client.command(bad, lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"{bad} 应被拒绝")

        self._scan_first_ap()
        ok, lines = self.client.command("WNM 0 cand 10 6 02AABBCCDDEE",
                                        lambda l: l.startswith("OK WNM "), 5)
        self.assertIsNotNone(ok, "WNM 启动失败")
        self.assertIn("mode=cand", ok)
        self.assertTrue(any(l.startswith("OK WNMSTA") for l in lines),
                        "显式 STA 注册应有回执")
        time.sleep(1.2)
        info = self._status()
        print(f"\n  wnmf={info.get('wnmf')} wnmc={info.get('wnmc')} wnm={info.get('wnm')}")
        self.assertEqual(info.get("wnm"), "cand")
        self.assertGreater(int(info.get("wnmf", "0")), 0, "BTM Request 应已发出")
        stop, _ = self.client.command("WNMSTOP", lambda l: l.startswith("OK WNMSTOP"), 5)
        self.assertIsNotNone(stop)
        self.assertEqual(self._status().get("wnm"), "off")

    def test_tim_frame_and_run(self):
        """TIM 篡改：DTIM count 归 0，bitmap 按 AID 置位；时间戳由 MAC 写，不是我们。"""
        self.client.send("TIMTEST")
        line, lines = self.client.command("", lambda l: l.startswith("TIMTEST beacon hex="), 6)
        self.assertIsNotNone(line, "TIMTEST 无输出")
        text = "\n".join(lines)
        self.assertIn("tim len=", text)
        self.assertIn("dtim_count=0", text, "DTIM count 应为 0（每个 beacon 都是 DTIM）")
        self.assertIn("bitmap=08", text, "AID 3 必须落在 bitmap 的第 3 位（0x08）")
        self.assertIn("bmp_mask=0x00000008", text, "位图掩码应与空口字节一致（这里是空的 AID 3）")

        for bad in ("TIM 0 nope", "TIM 0 tim 999"):
            line, _ = self.client.command(bad, lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"{bad} 应被拒绝")

        self._scan_first_ap()
        ok, _ = self.client.command("TIM 0 tim 3", lambda l: l.startswith("OK TIM "), 5)
        self.assertIsNotNone(ok, "TIM 启动失败")
        time.sleep(1.2)
        info = self._status()
        print(f"\n  tim={info.get('tim')} timf={info.get('timf')} "
              f"timreal={info.get('timreal')}")
        self.assertEqual(info.get("tim"), "tim")
        self.assertGreater(int(info.get("timf", "0")), 0, "克隆 beacon 应已发出")
        self.assertGreater(int(info.get("timreal", "0")), 0, "应已学到真 AP 的 beacon")
        stop, _ = self.client.command("TIMSTOP", lambda l: l.startswith("OK TIMSTOP"), 5)
        self.assertIsNotNone(stop)
        self.assertIn("real_beacons=", stop)

    def test_eapol_frame_format(self):
        """EAPOL：ToDS 数据帧 + LLC/SNAP 0x888E + type 1/2，QoS 变体 TID=6。"""
        self.client.send("EAPOLTEST")
        line, _ = self.client.command("", lambda l: l.startswith("EAPOLTEST start plain"), 6)
        self.assertIsNotNone(line, "EAPOLTEST 无输出")
        self.assertIn("fc=0x0108", line, "应为 ToDS 数据帧 (0x0108)")
        self.assertIn("snap=AAAA03", line)
        self.assertIn("etype=888E", line, "EtherType 必须是 0x888E")
        self.assertIn("ver=2 type=1", line, "EAPOL-Start")

        line, _ = self.client.command("", lambda l: l.startswith("EAPOLTEST logoff qos"), 6)
        self.assertIsNotNone(line)
        self.assertIn("tid=6", line, "QoS 变体应用 TID 6（wpa_supplicant 的 EAPOL TID）")
        self.assertIn("type=2", line, "EAPOL-Logoff")

        for bad in ("EAPOL 0 9", "EAPOL 0 6 notamac"):
            line, _ = self.client.command(bad, lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"{bad} 应被拒绝")

    def test_pspoll_frame_format_and_run(self):
        """PM 位三种帧型：Null Data / QoS Null / 单播 Action，PM=0 版本只差那一位。"""
        self.client.send("PSPOLLTEST")
        line, lines = self.client.command("", lambda l: l.startswith("PSPOLLTEST awake"), 6)
        self.assertIsNotNone(line, "PSPOLLTEST 无输出")
        text = "\n".join(lines)
        self.assertIn("fc=0x1148", text, "Null Data: ToDS + PM=1")
        self.assertIn("pm=1", text)
        self.assertIn("tods=1", text)
        self.assertIn("fc=0x11C8", text, "QoS Null: subtype 12 + PM=1")
        self.assertIn("tid=0", text, "QoS Control 的 TID 应为 0")
        # 管理帧没有 ToDS/FromDS 位，Action 帧的控制字节只有 PM 这一位
        self.assertIn("fc=0x10D0", text, "Action: mgmt subtype 13 + PM=1")
        self.assertIn("cat=127", text, "厂商自定义类别不属于 PMF 的 robust 集合")
        self.assertIn("pspolltest awake len=24 fc=0x0148 pm=0".replace("pspolltest", "PSPOLLTEST"),
                      text, "awake 版本必须清掉 PM 位")

        # 参数校验要在一个有效索引上做，否则先撞上"index out of range"
        self._scan_first_ap()

        # poll/both 已删除（单播 PS-Poll 发不出去），要给出明确错误而不是"未知参数"
        for bad in ("PSPOLL 0 poll", "PSPOLL 0 both"):
            err, _ = self.client.command(bad, lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(err, f"{bad} 应被拒绝")
            self.assertIn("PS-Poll", err, "错误信息要点明 PS-Poll 不可用")
        err, _ = self.client.command("PSPOLL 0 nonsense",
                                     lambda l: l.startswith("ERR "), 3)
        self.assertIsNotNone(err, "未知参数应被拒绝")

        ok, _ = self.client.command("PSPOLL 0 02AABBCCDDEE qosnull",
                                    lambda l: l.startswith("OK PSPOLL "), 5)
        self.assertIsNotNone(ok, "PM 位欺骗启动失败")
        self.assertIn("frame=qosnull", ok, "帧型应写进回执")
        self.assertIn("sta=02:AA:BB:CC:DD:EE", ok, "显式 STA 应写进回执")
        self.assertIn("chset=0", ok, "信道设置必须成功（否则帧会从扫描残留的信道出去）")
        time.sleep(1.5)
        info = self._status()
        print(f"\n  psp={info.get('psp')} pspfrm={info.get('pspfrm')} "
              f"pspf={info.get('pspf')} pspnul={info.get('pspnul')} "
              f"pspfl={info.get('pspfl')} pspdl={info.get('pspdl')}")
        self.assertEqual(info.get("psp"), "pm")
        self.assertEqual(info.get("pspfrm"), "qosnull")
        self.assertGreater(int(info.get("pspf", "0")), 0, "帧应已发出")
        self.assertGreater(int(info.get("pspfl", "0")), 0, "应已发出 PM=0 的释放帧")

        rel, _ = self.client.command("PSPOLLREL", lambda l: l.startswith("OK PSPOLLREL"), 5)
        self.assertIsNotNone(rel, "PSPOLLREL 无响应")
        self.assertIn("flushed=", rel)
        self.assertEqual(self._status().get("psp"), "off", "释放后应停止")

    def test_sae_frame_format_and_run(self):
        """SAE Commit：algorithm 3 / seq 1 / group 19 / P-256 生成元 + token 容器回显。"""
        self.client.send("SAETEST")
        line, lines = self.client.command("", lambda l: l.startswith("SAETEST security="), 6)
        self.assertIsNotNone(line, "SAETEST 无输出")
        text = "\n".join(lines)
        self.assertIn("len=128", text, "group 19 的 Commit 应为 128 字节")
        self.assertIn("alg=3 seq=1 status=0", text)
        self.assertIn("group=19", text)
        self.assertIn("elem=p256-generator", text, "默认应发合法曲线点（不是随机垃圾）")
        self.assertIn("token_eid=255 token_ext=93", text,
                      "反 clogging token 应装在 Element 255 / Ext 93 容器里")

        for bad in ("SAE 0 nope", "SAE 0 point 5000"):
            line, _ = self.client.command(bad, lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"{bad} 应被拒绝")

        self._scan_first_ap()
        # 过小的节拍会被抬到 50 ms（20 帧/s）：单播缓存在重传期间被占住，池子排水速率约
        # 32 帧/s，比它快就会在几秒内打满并触发 0x101 重启。要更快只能改固件，不能靠参数。
        ok, _ = self.client.command("SAE 0 point 20", lambda l: l.startswith("OK SAE "), 5)
        self.assertIsNotNone(ok, "SAE 启动失败")
        self.assertIn("gap_ms=50", ok, "gap_ms=20 应被抬到 50 ms")
        self.client.command("SAESTOP", lambda l: l.startswith("OK SAESTOP"), 5)

        ok, _ = self.client.command("SAE 0 point 100", lambda l: l.startswith("OK SAE "), 5)
        self.assertIsNotNone(ok, "SAE 启动失败")
        time.sleep(1.5)
        info = self._status()
        print(f"\n  saef={info.get('saef')} saec={info.get('saec')} "
              f"saeresp={info.get('saeresp')} saecode={info.get('saecode')} "
              f"saesec={info.get('saesec')}")
        self.assertEqual(info.get("sae"), "on")
        self.assertGreater(int(info.get("saef", "0")), 0, "Commit 应已发出")
        stop, _ = self.client.command("SAESTOP", lambda l: l.startswith("OK SAESTOP"), 5)
        self.assertIsNotNone(stop)

    def test_authflood_frame_format_and_run(self):
        """Auth/Assoc 洪泛：algorithm 0 / seq 1、Assoc Request 带目标 SSID 与 RSN IE。"""
        self.client.send("AUTHFLOODTEST")
        line, _ = self.client.command("", lambda l: l.startswith("AUTHFLOODTEST auth len="), 6)
        self.assertIsNotNone(line, "AUTHFLOODTEST 无输出")
        self.assertIn("alg=0 seq=1 status=0", line)

        line, _ = self.client.command("", lambda l: l.startswith("AUTHFLOODTEST assoc"), 6)
        self.assertIsNotNone(line)
        self.assertIn("cap=0x0411", line, "Assoc Request 的 capability 应带 ESS+Privacy")
        self.assertIn("listen=10", line)

        for bad in ("AUTHFLOOD 0 nope",):
            line, _ = self.client.command(bad, lambda l: l.startswith("ERR "), 3)
            self.assertIsNotNone(line, f"{bad} 应被拒绝")

        self._scan_first_ap()
        ok, _ = self.client.command("AUTHFLOOD 0 both noauto",
                                    lambda l: l.startswith("OK AUTHFLOOD "), 5)
        self.assertIsNotNone(ok, "AUTHFLOOD 启动失败")
        self.assertIn("auto=0", ok)
        time.sleep(1.5)
        info = self._status()
        print(f"\n  aff={info.get('aff')} afa={info.get('afa')} afs={info.get('afs')} "
              f"afids={info.get('afids')} afst={info.get('afst')}")
        self.assertEqual(info.get("af"), "on")
        self.assertGreater(int(info.get("aff", "0")), 0, "帧应已发出")
        self.assertGreaterEqual(int(info.get("afids", "0")), 1, "应已轮换出至少一个身份")
        stop, _ = self.client.command("AUTHFLOODSTOP",
                                      lambda l: l.startswith("OK AUTHFLOODSTOP"), 5)
        self.assertIsNotNone(stop)


if __name__ == "__main__":
    unittest.main(verbosity=2)
