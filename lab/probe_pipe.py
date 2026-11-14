"""Check the esp_sdr_wifi capture pipe: does it exist, and what does it emit?

The C5 capture firmware is supposed to publish frames on a Win32 named pipe so
tshark/our own decoder can read them. This helper only reports what the host can
see, so "tshark shows a duration that does not match" can be narrowed down to
`pipe missing / pipe present but empty / frames look sane`.

    python lab/probe_pipe.py                 # existence + 5 s of bytes
    python lab/probe_pipe.py --name esp_sdr_wifi --seconds 5
    python lab/probe_pipe.py --hex 512       # dump the first bytes as hex
"""
import argparse
import os
import threading
import time


def listed_pipes():
    try:
        names = os.listdir("\\\\.\\pipe\\")
    except OSError as exc:
        print("cannot enumerate pipes: %r" % (exc,))
        return []
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="esp_sdr_wifi")
    ap.add_argument("--seconds", type=float, default=5.0)
    ap.add_argument("--hex", type=int, default=128)
    args = ap.parse_args()

    path = "\\\\.\\pipe\\" + args.name
    names = listed_pipes()
    hits = [n for n in names if any(k in n.lower() for k in ("esp", "sdr", "wlan", "cap"))]
    print("pipes visible to this user: %d (matching: %s)" % (len(names), hits or "-"))

    out = {}

    def reader():
        try:
            with open(path, "rb", buffering=0) as pipe:
                out["data"] = pipe.read(args.hex)
        except Exception as exc:  # noqa: BLE001 - report whatever the host says
            out["error"] = repr(exc)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(args.seconds)
    if "error" in out:
        print("%s -> %s" % (path, out["error"]))
    elif "data" in out:
        data = out["data"]
        print("%s -> %d bytes: %s" % (path, len(data), data.hex()))
    else:
        print("%s -> opened but nothing arrived in %.1f s (writer not connected?)"
              % (path, args.seconds))


if __name__ == "__main__":
    main()
