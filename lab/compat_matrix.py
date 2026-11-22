"""Reply-compatibility matrix for the wbus migration.

Runs every legacy command that has deterministic output twice, keeps only the lines
that came back identical in both runs (counters and scan results vary), and stores
that as the baseline. After refactoring, `check` mode re-runs the same list and
diffs against the baseline -- any drift in wording, argument order or defaults shows
up as a one-line diff.

    python lab/compat_matrix.py baseline   # before the refactor
    python lab/compat_matrix.py check      # after
"""
import json
import sys
import time
from pathlib import Path

import serial

PORT = "COM5"
BASELINE = Path(__file__).with_name("compat_baseline.json")

# (command, seconds to collect). Validation errors answer immediately; the OK lines
# of a start command are also immediate, so most entries need < 1 s.
COMMANDS = [
    ("DEAUTH", 0.6), ("DEAUTH 0", 0.8), ("DEAUTH 9999", 0.6), ("DEAUTH 0 0", 0.6),
    ("DEAUTH 0 70000", 0.6), ("DEAUTH abc", 0.6), ("DEAUTH 3x", 0.6),
    ("DEAUTH_ALL", 0.6), ("DEAUTH_ONLY", 0.6), ("DEAUTH_ONLY 0", 0.8),
    ("DEAUTH_ONLY a,b", 0.6), ("DEAUTH_EXCEPT", 0.6), ("DEAUTH_EXCEPT 9999", 0.6),
    ("REASON", 0.6), ("REASON 7", 0.6), ("REASON random", 0.6), ("REASON 0", 0.6),
    ("DELBA", 0.6), ("DELBA 0", 0.8), ("DELBA 0 0", 0.6), ("DELBA 0 7", 0.6),
    ("DELBA 9999 37", 0.6), ("DELBA 0 abc", 0.6), ("DELBATEST", 1.0), ("DELBASTOP", 0.6),
    ("BAATTACK", 0.6), ("BAATTACK 0", 0.8), ("BAATTACK 9999", 0.6),
    ("BAPLANT", 0.6), ("BAPLANT 0 0", 0.8), ("BARPUSH", 0.6), ("BARPUSH 0 0", 0.8),
    ("BATEST", 1.0), ("BATX", 0.8), ("BASTOP", 0.6),
    ("WNM", 0.6), ("WNM 0", 0.8), ("WNM 0 bare", 0.8), ("WNM 0 nope", 0.6),
    ("WNM 9999", 0.6), ("WNMTEST", 1.0), ("WNMSTOP", 0.6),
    ("TIM", 0.6), ("TIM 0", 0.8), ("TIM 0 clear 3", 0.8), ("TIM 0 nope", 0.6),
    ("TIM 9999", 0.6), ("TIMSTOP", 0.6),
    ("EAPOL", 0.6), ("EAPOL 0", 0.8), ("EAPOL 0 -1", 0.8), ("EAPOL 0 6 02:AA:BB:CC:DD:EE", 0.8),
    ("EAPOL 9999", 0.6), ("EAPOLTEST", 1.0), ("EAPOLSTOP", 0.6),
    ("PSPOLL", 0.6), ("PSPOLL 0", 0.8), ("PSPOLL 0 null", 0.8), ("PSPOLL 0 action", 0.8),
    ("PSPOLL 0 02:AA:BB:CC:DD:EE qosnull", 0.8), ("PSPOLL 0 poll", 0.6),
    ("PSPOLL 9999", 0.6), ("PSPOLLTEST", 1.0), ("PSPOLLREL", 0.8), ("PSPOLLSTOP", 0.6),
    ("SAE", 0.6), ("SAE 0", 0.8), ("SAE 0 rand 200", 0.8), ("SAE 0 nope", 0.6),
    ("SAE 9999", 0.6), ("SAETEST", 1.0), ("SAESTOP", 0.6),
    ("AUTHFLOOD", 0.6), ("AUTHFLOOD 0", 0.8), ("AUTHFLOOD 0 auth", 0.8),
    ("AUTHFLOOD 0 both noauto", 0.8), ("AUTHFLOOD 0 nope", 0.6), ("AUTHFLOOD 9999", 0.6),
    ("AUTHFLOODTEST", 1.0), ("AUTHFLOODSTOP", 0.6),
    ("CSA", 0.6), ("CSA 0 nope", 0.6), ("CSA 0 3 1", 0.6), ("CSA 0 999", 0.6),
    ("CSASTOP", 0.6), ("CSATEST", 1.0),
    ("STOP", 0.6), ("WBUS", 0.6), ("DESCRIBE csa", 0.6),
]


def open_port():
    ser = serial.Serial(PORT, 115200, timeout=0.1)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.3)
    return ser


def read_lines(ser, duration):
    end = time.time() + duration
    buf = b""
    out = []
    while time.time() < end:
        chunk = ser.read(4096)
        if chunk:
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace").rstrip("\r")
                if text:
                    out.append(text)
    return out


def run_matrix(ser):
    result = {}
    read_lines(ser, 0.3)
    ser.write(b"STOP\r\n")
    ser.flush()
    read_lines(ser, 0.3)
    ser.write(b"SCAN\r\n")
    ser.flush()
    deadline = time.time() + 30
    while time.time() < deadline:
        if any(l.startswith("SCAN_END") for l in read_lines(ser, 0.5)):
            break
    for command, duration in COMMANDS:
        ser.write(command.encode() + b"\r\n")
        ser.flush()
        result[command] = read_lines(ser, duration)
        if command.startswith(("DEAUTH", "DELBA", "BA", "WNM", "TIM", "EAPOL", "PSPOLL",
                               "SAE", "AUTHFLOOD", "CSA")):
            ser.write(b"STOP\r\n")
            ser.flush()
            read_lines(ser, 0.3)
    return result


def stable_lines(first, second):
    """Lines that came back identical (and in the same relative order) in both runs."""
    if first == second:
        return first, True
    keep = []
    common = set(first) & set(second)
    for line in first:
        if line in common:
            keep.append(line)
            common.discard(line)
    return keep, False


# Words that carry meaning in an OK line and must survive the skeleton reduction.
MODE_WORDS = {
    "auto", "fixed", "auto(opposite-band)", "point", "rand", "cand-bssid", "nbr", "tim",
    "clear", "both", "auth", "assoc", "noauto", "null", "qosnull", "action", "all",
    "none", "on", "off", "pm", "upgraded", "single", "multi",
}


def canon(line):
    """Compare wording, not volatile values.

    ERR/INFO/WARN lines must match byte for byte -- that is the text scripts and the
    test suite key on. OK/…TEST lines are reduced to their skeleton: the command, the
    argument names, the mode words, with every number/SSID/MAC masked. Hex dumps are
    dropped entirely because they carry random elements and learned IEs.
    """
    if "hex=" in line:
        return None
    head = line.split(" ", 1)[0]
    if head in ("ERR", "INFO", "WARN"):
        return line
    parts = []
    for token in line.split():
        if "=" in token:
            parts.append(token.split("=", 1)[0] + "=#")
        elif token in MODE_WORDS:
            parts.append(token)
        else:
            # Everything else is data: an SSID, a MAC, a channel, a reason code.
            parts.append("#")
    return " ".join(parts)


# Answers that depend on how many APs this scan happened to return, not on the code.
SCAN_DEPENDENT = {"DEAUTH 3x"}


def compare(command, expected, got):
    """expected must appear in got in order (volatile lines may be interleaved)."""
    position = 0
    for want in expected:
        wanted = canon(want)
        if wanted is None:
            continue
        while position < len(got):
            if canon(got[position]) == wanted:
                position += 1
                break
            position += 1
        else:
            if command in SCAN_DEPENDENT and got and got[0].startswith("ERR index out of range"):
                return True  # fewer APs this round: same code, different scan
            return False
    return True


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    ser = open_port()
    try:
        if mode == "baseline":
            first = run_matrix(ser)
            second = run_matrix(ser)
            baseline = {}
            unstable = []
            for command, _ in COMMANDS:
                keep, same = stable_lines(first[command], second[command])
                baseline[command] = keep
                if not same:
                    unstable.append(command)
            BASELINE.write_text(json.dumps(baseline, ensure_ascii=False, indent=1), encoding="utf-8")
            print(f"baseline: {len(baseline)} commands, {len(unstable)} unstable")
            for command in unstable:
                print(f"  unstable: {command}")
        else:
            baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
            current = run_matrix(ser)
            diffs = 0
            for command, expected in baseline.items():
                got = current.get(command, [])
                if not compare(command, expected, got):
                    diffs += 1
                    print(f"\nDIFF {command}")
                    print(f"  expected: {[canon(l) for l in expected]}")
                    print(f"  got     : {[canon(l) for l in got]}")
            print(f"\n{diffs} command(s) differ out of {len(baseline)}")
            return 1 if diffs else 0
    finally:
        ser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
