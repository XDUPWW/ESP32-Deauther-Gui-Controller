"""ESP32-Deauther 串口协议解析（纯函数，无 I/O、无 Tk，便于单元测试）。

固件输出行：
    OK <...> / ERR <...> / INFO <...>
    STATUS mode=.. eliminated=.. networks=.. creds=.. heap=.. caps=..
    SCAN_BEGIN / NET <idx> <rssi> <ch> <enc> <bssid> <ssid> / SCAN_END <n>
    CREDS_BEGIN / CRED <i> <user> <pass> <ts> / CREDS_END <n>
"""

BAND_5G_MIN_CHANNEL = 15  # >14 就是 5 GHz


def band_of_channel(channel):
    try:
        return "5G" if int(channel) >= BAND_5G_MIN_CHANNEL else "2.4G"
    except (TypeError, ValueError):
        return "?"


def parse_net(line):
    """解析 NET 行；SSID 允许含空格，放在最后。失败返回 None。"""
    if not line.startswith("NET "):
        return None
    parts = line.split(" ", 6)
    if len(parts) < 6:
        return None
    try:
        index = int(parts[1])
        rssi = int(parts[2])
        channel = int(parts[3])
    except ValueError:
        return None
    return {
        "index": index,
        "rssi": rssi,
        "channel": channel,
        "enc": parts[4],
        "bssid": parts[5].upper(),
        "ssid": parts[6] if len(parts) > 6 else "",
        "band": band_of_channel(channel),
    }


def parse_status(line):
    """解析 STATUS 行的 key=value 字段。失败返回空 dict。"""
    if not line.startswith("STATUS "):
        return {}
    info = {}
    for token in line.split(" ")[1:]:
        if "=" in token:
            key, value = token.split("=", 1)
            info[key] = value
    return info


def parse_caps(status_info):
    """caps=deauth,eviltwin,5g -> set。"""
    raw = status_info.get("caps", "")
    return {item for item in raw.split(",") if item}


def parse_cred(line):
    """解析 CRED 行。"""
    if not line.startswith("CRED "):
        return None
    parts = line.split(" ", 5)
    if len(parts) < 5:
        return None
    return {"index": parts[1], "username": parts[2], "password": parts[3], "timestamp": parts[4]}


def classify(line):
    """把一行固件输出归类，返回 (kind, payload)。

    kind 取值: net / scan_begin / scan_end / status / cred / creds_begin /
              creds_end / ok / err / info / empty / raw
    """
    if line is None:
        return ("empty", None)
    line = line.rstrip()
    if not line:
        return ("empty", None)
    if line.startswith("NET "):
        return ("net", parse_net(line))
    if line == "SCAN_BEGIN":
        return ("scan_begin", None)
    if line.startswith("SCAN_END"):
        parts = line.split(" ")
        count = parts[1] if len(parts) > 1 else ""
        return ("scan_end", count)
    if line.startswith("STATUS "):
        return ("status", parse_status(line))
    if line.startswith("CRED "):
        return ("cred", parse_cred(line))
    if line == "CREDS_BEGIN":
        return ("creds_begin", None)
    if line.startswith("CREDS_END"):
        parts = line.split(" ")
        return ("creds_end", parts[1] if len(parts) > 1 else "")
    if line.startswith("OK "):
        return ("ok", line[3:])
    if line.startswith("ERR "):
        return ("err", line[4:])
    if line.startswith("INFO "):
        return ("info", line[5:])
    return ("raw", line)


def mode_is_attacking(mode):
    """STATUS 里的 mode 是否表示"正在攻击"。"""
    return mode not in (None, "", "idle")
