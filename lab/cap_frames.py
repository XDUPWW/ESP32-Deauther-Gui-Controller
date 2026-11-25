"""Decode the frames the new attack modules inject, straight off the C5 capture pipe.

    python lab/cap_frames.py --seconds 6
    python lab/cap_frames.py --seconds 6 --save cap.pcap
    python lab/cap_frames.py --file cap.pcap --bssid BE:41:99:0B:20:36

What it proves (one line per frame family, with the fields that matter):
  * BTM    management subtype 13, category 10, action 7 -> request mode, timer,
           validity interval, and the Neighbor Report candidate
  * RRM    management subtype 13, category 5, action 5 -> dialog token, Protected
           bit, and the Neighbor Report element (id 52): BSSID, information word,
           operating class, channel, PHY type
  * TIM    management subtype 8 beacon with the target BSSID -> TIM element
           (DTIM count/period, bitmap); the timestamp field is the MAC's, not ours
  * BSRP   control subtype 2, Trigger Type 4 -> common scheduling fields, AID12,
           RU region/allocation, MCS and Target RSSI from the 40-bit User Info
  * EAPOL  data frame whose LLC/SNAP carries EtherType 0x888E -> EAPOL version/type
  * SAE    management subtype 11 with algorithm 3 -> group, scalar/element sizes
  * AUTH    management subtype 11 with algorithm 0 -> transaction sequence
It also counts how many frames carry a locally administered transmitter address,
i.e. the ones this firmware forged.
"""
import argparse
import collections
import sys
import threading

import cap_pipe


def fmt_mac(raw, off):
    return cap_pipe.mac(raw, off)


def decode_trigger(pkt, ta, out):
    """HE Trigger common fields and the first Basic/BSRP User Info field."""
    common = int.from_bytes(pkt[16:24], "little")
    trigger_type = common & 0xF
    out["trigger"] += 1
    out["trigger_type_%d" % trigger_type] += 1
    fields = ("len=%d ta=%s ra=%s type=%d ul_length=%d more_tf=%d cs_required=%d "
              "ul_bw=%d gi_ltf=%d he_ltf=%d ap_tx_power=%d spatial_reuse=0x%04X "
              "doppler=%d" % (
                  len(pkt), ta, fmt_mac(pkt, 4), trigger_type, (common >> 4) & 0xFFF,
                  (common >> 16) & 1, (common >> 17) & 1, (common >> 18) & 3,
                  (common >> 20) & 3, (common >> 23) & 7, (common >> 28) & 0x3F,
                  (common >> 37) & 0xFFFF, (common >> 53) & 1))
    if trigger_type == 4 and len(pkt) >= 29:
        out["bsrp"] += 1
        user = int.from_bytes(pkt[24:29], "little")
        fields += (" aid=%d ru_region=%d ru_allocation=%d fec=%d mcs=%d dcm=%d "
                   "ss_start=%d ss_count=%d target_rssi=%d padding=%s" % (
                       user & 0xFFF, (user >> 12) & 1, (user >> 13) & 0x7F,
                       (user >> 20) & 1, (user >> 21) & 0xF, (user >> 25) & 1,
                       (user >> 26) & 7, (user >> 29) & 7, (user >> 32) & 0x7F,
                       pkt[29:].hex().upper()))
    if len(out["trigger_samples"]) < 6:
        out["trigger_samples"].append(fields)


def decode_rrm(pkt, ta, out):
    """802.11k Radio Measurement actions: requests/reports/neighbor reports."""
    act = pkt[25]
    protected = (pkt[1] & 0x40) >> 6
    if act == 5:
        out["rrm_nbr"] += 1
        token = pkt[26] if len(pkt) > 26 else -1
        cand = " no-element"
        if len(pkt) >= 42 and pkt[27] == 52:
            # eid(27) len(28) bssid(29..34) info(35..38 LE) op_class(39) ch(40) phy(41)
            info = pkt[35] | (pkt[36] << 8) | (pkt[37] << 16) | (pkt[38] << 24)
            cand = (" eid=52 ie_len=%d cand_bssid=%s info=0x%08X op_class=%d ch=%d phy=%d"
                    % (pkt[28], fmt_mac(pkt, 29), info, pkt[39], pkt[40], pkt[41]))
        if len(out["rrm_samples"]) < 3:
            out["rrm_samples"].append(
                "len=%d ta=%s ra=%s token=%d protected=%d%s"
                % (len(pkt), ta, fmt_mac(pkt, 4), token, protected, cand))
    elif act == 4:
        out["rrm_nbr_req"] += 1
        if len(out["rrm_req_samples"]) < 3:
            out["rrm_req_samples"].append(
                "len=%d ta=%s ra=%s token=%d protected=%d"
                % (len(pkt), ta, fmt_mac(pkt, 4), pkt[26] if len(pkt) > 26 else -1, protected))
    else:
        out["rrm_other"] += 1


def decode(pkt, bssid_filter, out):
    if len(pkt) < 10:
        return
    ftype = (pkt[0] >> 2) & 0x3
    subtype = (pkt[0] >> 4) & 0xF
    ta = fmt_mac(pkt, 10) if len(pkt) >= 16 else "-"
    forged = ta.startswith("02:")
    bssid = fmt_mac(pkt, 16) if len(pkt) >= 24 else "-"

    if ftype == 1 and subtype == 2 and len(pkt) >= 24:
        decode_trigger(pkt, ta, out)

    if ftype == 0 and subtype == 13 and len(pkt) >= 26:
        cat, act = pkt[24], pkt[25]
        if cat == 10 and act == 7:
            out["btm"] += 1
            if len(pkt) >= 31:
                mode = pkt[27]
                timer = pkt[28] | (pkt[29] << 8)
                validity = pkt[30]
                cand = ""
                if len(pkt) >= 46 and pkt[31] == 52:
                    # cand: eid(31) len(32) bssid(33..38) info(39..42) op_class(43) ch(44) phy(45)
                    cand = " cand_bssid=%s op_class=%d ch=%d" % (
                        fmt_mac(pkt, 33), pkt[43], pkt[44])
                if len(out["btm_samples"]) < 3:
                    out["btm_samples"].append(
                        "len=%d ta=%s ra=%s mode=0x%02X imm=%d candlist=%d timer=%d "
                        "validity=%d%s" % (len(pkt), ta, fmt_mac(pkt, 4), mode,
                                           (mode >> 2) & 1, mode & 1, timer, validity, cand))
        elif cat == 10 and act == 8:
            out["btm_resp"] += 1
            if len(out["btm_resp_samples"]) < 3:
                out["btm_resp_samples"].append(
                    "len=%d ta=%s ra=%s dialog=%d status=%d" % (
                        len(pkt), ta, fmt_mac(pkt, 4), pkt[26], pkt[27] if len(pkt) > 27 else -1))
        elif cat == 5:
            decode_rrm(pkt, ta, out)
        else:
            out["other_action"] += 1

    if ftype == 0 and subtype == 11 and len(pkt) >= 30:
        alg = pkt[24] | (pkt[25] << 8)
        seq = pkt[26] | (pkt[27] << 8)
        status = pkt[28] | (pkt[29] << 8)
        if alg == 3:
            out["sae"] += 1
            group = (pkt[30] | (pkt[31] << 8)) if len(pkt) >= 32 else -1
            if len(out["sae_samples"]) < 3:
                out["sae_samples"].append(
                    "len=%d ta=%s ra=%s seq=%d status=%d group=%d body_after_group=%d" % (
                        len(pkt), ta, fmt_mac(pkt, 4), seq, status, group,
                        len(pkt) - 32 if group >= 0 else -1))
        elif alg == 0:
            out["auth"] += 1
            if len(out["auth_samples"]) < 3:
                out["auth_samples"].append(
                    "len=%d ta=%s ra=%s seq=%d status=%d" % (
                        len(pkt), ta, fmt_mac(pkt, 4), seq, status))
        if status == 76:
            out["sae_token_resp"] += 1
            if len(out["token_samples"]) < 3:
                out["token_samples"].append(
                    "len=%d ra=%s token_bytes=%d head=%s" % (
                        len(pkt), fmt_mac(pkt, 4), len(pkt) - 30,
                        " ".join("%02X" % b for b in pkt[30:38])))

    if ftype == 0 and subtype == 8 and bssid_filter and bssid == bssid_filter:
        out["beacon_target"] += 1
        tsf = int.from_bytes(pkt[24:32], "little")
        interval = pkt[32] | (pkt[33] << 8)
        # Walk the IEs for TIM and SSID.
        tim = None
        ssid = None
        pos = 36
        while pos + 2 <= len(pkt):
            eid, elen = pkt[pos], pkt[pos + 1]
            if pos + 2 + elen > len(pkt):
                break
            if eid == 5 and elen >= 3:
                tim = (pkt[pos + 2], pkt[pos + 3], pkt[pos + 4],
                       "".join("%02X" % b for b in pkt[pos + 5:pos + 2 + elen]))
            elif eid == 0:
                ssid = pkt[pos + 2:pos + 2 + elen].decode("utf-8", "replace")
            pos += 2 + elen
        if tim is not None:
            out["beacon_clone"] += 1
            seq = (pkt[22] >> 4) | (pkt[23] << 4)
            if seq == 0xFFF:
                out["beacon_forged_seq"] += 1
            if len(out["beacon_samples"]) < 4:
                out["beacon_samples"].append(
                    "ta=%s seq=0x%03X tsf=%d interval=%d ssid=%r tim(dtim_count=%d period=%d "
                    "ctrl=0x%02X bmp=%s)" % (ta, seq, tsf, interval, ssid, tim[0], tim[1],
                                             tim[2], tim[3]))

    if ftype == 2 and len(pkt) >= 24:
        if pkt[1] & 0x40:
            return  # protected bit: the payload is ciphertext, not a cleartext LLC/SNAP
        header = 24
        if (pkt[1] & 0x03) == 0x03:
            header += 6
        if subtype & 0x08:
            header += 2
        if pkt[1] & 0x80:
            header += 4
        if len(pkt) >= header + 12 and pkt[header] == 0xAA and pkt[header + 1] == 0xAA \
                and pkt[header + 2] == 0x03 and pkt[header + 6] == 0x88 \
                and pkt[header + 7] == 0x8E:
            ver = pkt[header + 8]
            etype = pkt[header + 9]
            body = pkt[header + 10] | (pkt[header + 11] << 8)
            out["eapol"] += 1
            if etype == 1:
                out["eapol_start"] += 1
            elif etype == 2:
                out["eapol_logoff"] += 1
            elif etype == 0:
                out["eapol_eap"] += 1
            if len(out["eapol_samples"]) < 4:
                out["eapol_samples"].append(
                    "len=%d subtype=%d ta=%s ra=%s ver=%d type=%d body_len=%d" % (
                        len(pkt), subtype, ta, fmt_mac(pkt, 4), ver, etype, body))
    if forged:
        out["forged_ta"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="esp_sdr_wifi")
    ap.add_argument("--seconds", type=float, default=6.0)
    ap.add_argument("--file", default=None)
    ap.add_argument("--save", default=None)
    ap.add_argument("--bssid", default=None, help="target BSSID for the beacon/TIM view")
    args = ap.parse_args()

    if args.file:
        blob = cap_pipe.read_file(args.file)
    else:
        result = {}
        t = threading.Thread(target=cap_pipe.read_pipe, args=(args.name, args.seconds, result))
        t.start()
        t.join()
        if "error" in result:
            print("pipe %s -> %s" % (args.name, result["error"]))
            return 1
        blob = result.get("data", b"")
        print("captured %d bytes in %.1f s" % (len(blob), args.seconds))
        if args.save:
            with open(args.save, "wb") as f:
                f.write(blob)
            print("saved %s" % args.save)

    bssid_filter = args.bssid.upper() if args.bssid else None
    out = collections.defaultdict(int)
    for key in ("btm_samples", "btm_resp_samples", "rrm_samples", "rrm_req_samples",
                "trigger_samples", "sae_samples", "auth_samples", "token_samples",
                "beacon_samples", "eapol_samples"):
        out[key] = []

    total = 0
    for _ts, pkt, linktype in cap_pipe.parse_pcap(blob):
        if linktype == 127:
            pkt = cap_pipe.skip_radiotap(pkt)
        total += 1
        decode(pkt, bssid_filter, out)

    print("frames: %d  forged-TA(02:..)=%d" % (total, out["forged_ta"]))
    print("BTM BTM Request=%d  BTM Response=%d  other action=%d"
          % (out["btm"], out["btm_resp"], out["other_action"]))
    for s in out["btm_samples"]:
        print("  btm: %s" % s)
    for s in out["btm_resp_samples"]:
        print("  btm-response: %s" % s)
    print("RRM neighbor report resp=%d  neighbor report req=%d  other cat5 action=%d"
          % (out["rrm_nbr"], out["rrm_nbr_req"], out["rrm_other"]))
    for s in out["rrm_samples"]:
        print("  rrm: %s" % s)
    for s in out["rrm_req_samples"]:
        print("  rrm-req: %s" % s)
    print("Trigger frames=%d  BSRP(type=4)=%d  other types=%d"
          % (out["trigger"], out["bsrp"], out["trigger"] - out["bsrp"]))
    for s in out["trigger_samples"]:
        print("  trigger: %s" % s)
    print("SAE commit(alg=3)=%d  auth(alg=0)=%d  status76 answers=%d"
          % (out["sae"], out["auth"], out["sae_token_resp"]))
    for s in out["sae_samples"]:
        print("  sae: %s" % s)
    for s in out["auth_samples"]:
        print("  auth: %s" % s)
    for s in out["token_samples"]:
        print("  anti-clogging: %s" % s)
    print("EAPOL frames=%d (start=%d logoff=%d eap=%d)"
          % (out["eapol"], out["eapol_start"], out["eapol_logoff"], out["eapol_eap"]))
    for s in out["eapol_samples"]:
        print("  eapol: %s" % s)
    print("target beacons=%d (of them forged seq=0xFFF: %d)  clone candidates(TIM seen)=%d"
          % (out["beacon_target"], out["beacon_forged_seq"], out["beacon_clone"]))
    for s in out["beacon_samples"]:
        print("  beacon: %s" % s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
