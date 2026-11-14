"""Read the esp_sdr_wifi capture pipe and decode the control frames in it.

The C5 firmware (or its host helper) publishes a pcap stream on a Win32 named pipe:
global header `d4 c3 b2 a1`, linktype 127 (802.11 + radiotap). tshark is not needed
here -- this parses the pcap and the radiotap header itself, so a "the RTS claims
990 ms" report can be traced down to the actual bytes.

    python lab/cap_pipe.py --seconds 8                    # live from the pipe
    python lab/cap_pipe.py --file cap.pcap                # from a saved capture
    python lab/cap_pipe.py --seconds 8 --save cap.pcap    # keep it as well

What it prints, per control subtype: counts, the Duration/ID values (µs), and how
many frames carry a locally administered RA (`02:..`, i.e. forged by our firmware).
"""
import argparse
import collections
import os
import struct
import threading
import time


def read_pipe(name, seconds, out):
    path = "\\\\.\\pipe\\" + name
    deadline = time.time() + seconds
    data = bytearray()
    try:
        with open(path, "rb", buffering=0) as pipe:
            while time.time() < deadline:
                chunk = pipe.read(4096)
                if not chunk:
                    time.sleep(0.01)
                    continue
                data += chunk
    except Exception as exc:  # noqa: BLE001
        out["error"] = repr(exc)
    out["data"] = bytes(data)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def resync(blob):
    """Return (offset, linktype) of the first usable pcap record.

    The pipe server writes the pcap global header once when it starts, so a client
    that attaches later gets a stream that begins in the middle of a record. Either
    find the header, or rebuild one and brute-force the record boundary (a wrong
    alignment cannot parse more than a couple of records in a row because incl_len
    has to stay in a sane range).
    """
    idx = blob.find(b"\xd4\xc3\xb2\xa1")
    if idx >= 0:
        linktype = struct.unpack("<I", blob[idx + 20:idx + 24])[0] if idx + 24 <= len(blob) else 127
        return idx, linktype

    best_start, best_score = 0, -1
    limit = min(len(blob) - 16, 512)
    for start in range(limit):
        off, run = start, 0
        while off + 16 <= len(blob):
            _s, _u, incl, _o = struct.unpack("<IIII", blob[off:off + 16])
            if incl < 10 or incl > 4000 or off + 16 + incl > len(blob):
                break
            off += 16 + incl
            run += 1
        if run > best_score:
            best_start, best_score = start, run
    return best_start, 127


def parse_pcap(blob, radiotap=True):
    """Yield (ts, raw, linktype) per packet; stops at the first truncated record."""
    if len(blob) < 24:
        return
    off, linktype = resync(blob)
    if blob[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        off += 0 if off == 0 else 0  # records start at `off`, header synthesised
    else:
        off += 24
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl, _orig = struct.unpack("<IIII", blob[off:off + 16])
        off += 16
        if incl < 10 or incl > 4000 or off + incl > len(blob):
            return
        yield (ts_sec + ts_usec / 1e6, blob[off:off + incl], linktype)
        off += incl


def skip_radiotap(pkt):
    if len(pkt) < 8:
        return pkt
    ver = pkt[0]
    hlen = struct.unpack("<H", pkt[2:4])[0]
    if ver != 0 or hlen < 8 or hlen > len(pkt):
        return pkt
    return pkt[hlen:]


def mac(raw, off):
    return ":".join("%02X" % b for b in raw[off:off + 6])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="esp_sdr_wifi")
    ap.add_argument("--seconds", type=float, default=8.0)
    ap.add_argument("--file", default=None)
    ap.add_argument("--save", default=None)
    args = ap.parse_args()

    if args.file:
        blob = read_file(args.file)
    else:
        out = {}
        t = threading.Thread(target=read_pipe, args=(args.name, args.seconds, out))
        t.start()
        t.join()
        if "error" in out:
            print("pipe %s -> %s" % (args.name, out["error"]))
            return 1
        blob = out.get("data", b"")
        print("captured %d bytes in %.1f s" % (len(blob), args.seconds))
        if args.save:
            with open(args.save, "wb") as f:
                f.write(blob)
            print("saved %s" % args.save)

    counts = collections.Counter()
    durations = collections.defaultdict(collections.Counter)
    forged = collections.defaultdict(int)
    samples = collections.defaultdict(list)
    total = 0
    for _ts, pkt, linktype in parse_pcap(blob):
        if linktype == 127:
            pkt = skip_radiotap(pkt)
        if len(pkt) < 10:
            continue
        total += 1
        fc0, fc1 = pkt[0], pkt[1]
        ftype = (fc0 >> 2) & 0x3
        subtype = (fc0 >> 4) & 0xF
        if ftype != 1:  # only control frames matter here
            counts["type%d" % ftype] += 1
            continue
        name = {8: "BAR", 9: "BA", 10: "PSPoll", 11: "RTS", 12: "CTS", 13: "ACK",
                14: "CFEnd"}.get(subtype, "ctrl%d" % subtype)
        counts[name] += 1
        dur = struct.unpack("<H", pkt[2:4])[0] if subtype != 13 and subtype != 10 else 0
        durations[name][dur] += 1
        ra = mac(pkt, 4)
        if ra.startswith("02:"):
            forged[name] += 1
        if len(samples[name]) < 4:
            ta = mac(pkt, 10) if subtype in (8, 11, 14) else "-"
            samples[name].append("len=%d ra=%s ta=%s dur=%d" % (len(pkt), ra, ta, dur))

    print("packets: %d  (control: %s)" % (
        total, ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())) or "none"))
    for name in ("RTS", "CTS", "CFEnd", "BAR"):
        if name not in counts:
            continue
        print("\n%s: %d frames, forged-RA(02:..)=%d" % (name, counts[name], forged[name]))
        top = durations[name].most_common(8)
        print("  duration(us): %s" % ", ".join("%d×%d" % (v, c) for v, c in top))
        for s in samples[name]:
            print("  sample: %s" % s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
