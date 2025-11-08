#!/usr/bin/env python3
# 20251015_diagram.py (robust)
#
# Features:
# - Read iperf3 JSON or PCAP (via tshark)
# - Throughput Time Series (seconds; supports sub-second bins) [line only]
# - Throughput CDF [line only]
# - Jitter CDF (arrival-based, ms) [line only]
# - Latency CDF:
#     * single pair: --latpair tx:<pcap> rx:<pcap>
#     * multi-pairs: --latpairs "Label,tx:<pcap>,rx:<pcap>" ...
#   (IPv4/UDP; match by (ip.id, udp.length))
# - --outdir output folder
# - --annotate-means: multi-line header box with per-series mean Mbps
#
# Deps: Python 3.8+, numpy, matplotlib, tshark in PATH

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict

import numpy as np
import matplotlib.pyplot as plt

SUPPORTED_PCAP_EXT = (".pcap", ".pcapng", ".cap")

@dataclass
class Series:
    label: str
    rate_ts: np.ndarray                 # per-bin throughput (Mbps)
    rate_samples: np.ndarray            # throughput samples for CDF (Mbps)
    jitter_ms_samples: Optional[np.ndarray] = None
    mean_rate_mbps: Optional[float] = None
    p50_rate_mbps: Optional[float] = None
    p95_rate_mbps: Optional[float] = None
    loss_pct: Optional[float] = None    # from iperf3 JSON if present

def has_tshark() -> bool:
    return shutil.which("tshark") is not None

def parse_args():
    ap = argparse.ArgumentParser(
        description="Plot throughput/jitter from iperf3 JSON and PCAPs; plus latency CDF from paired PCAPs."
    )
    ap.add_argument("prefix", help="Output filename prefix")
    ap.add_argument("inputs", nargs="*", help="List like Label:file.json or Label:file.pcap (optional for latency-only)")
    ap.add_argument("--bpf", default="", help="BPF for throughput/jitter PCAPs (e.g., 'udp and port 5201')")
    ap.add_argument("--bin", type=float, default=1.0, help="Bin size for throughput in seconds (default: 1.0)")
    ap.add_argument("--smooth", type=int, default=0, help="Rolling window for smoothing timeseries (0 = off)")
    ap.add_argument("--outdir", default=".", help="Output directory for figures")
    ap.add_argument("--annotate-means", action="store_true", help="Show per-series mean Mbps at top (multi-line)")
    # Latency: single pair (backward compatible)
    ap.add_argument("--latpair", nargs="*", default=[], help="Single pair as tx:<pcap> rx:<pcap>")
    # Latency: multiple pairs, one figure; items like 'Label,tx:<pcap>,rx:<pcap>'
    ap.add_argument("--latpairs", nargs="*", default=[], help='Multiple pairs: "Label,tx:<pcap>,rx:<pcap>" ...')
    ap.add_argument("--bpf-lat", default="", help="BPF for latency pairs (applied to both tx/rx)")
    ap.add_argument("--lat-align", choices=["none", "min", "median"], default="none",
                    help="Alignment for one-way delay to mitigate clock offsets: 'none' (raw), 'min' (shift so min=0), 'median' (center at 0)")
    ap.add_argument("--lat-csv", default="", help="Optional CSV file to export latency samples; multi-pair includes label column")
    ap.add_argument("--lat-key", choices=["ipidlen", "tuple", "ports", "iperf3"], default="ipidlen",
                    help="Matching key: 'ipidlen'=(ip.id,udp.length) IPv4; 'tuple'=(src,dst,sport,dport,len); 'ports'=(sport,dport,len) NAT-tolerant; 'iperf3'=UDP payload seq")
    ap.add_argument("--lat-bound-ms", type=float, default=10000.0,
                    help="Absolute delay bound (ms) to accept raw pairs before alignment; set <=0 to disable (default: 10000 ms)")
    ap.add_argument("--lat-match", choices=["seq", "nearest"], default="seq",
                    help="Pairing mode within each flow key: 'seq' pairs by index (fast, assumes no loss/reorder); 'nearest' greedily matches nearest rx>=tx within a window")
    ap.add_argument("--lat-max-gap-ms", type=float, default=200.0,
                    help="For --lat-match nearest: maximum allowed time gap between tx and rx in milliseconds (default: 200 ms)")
    ap.add_argument("--deskew", choices=["off", "ls", "robust"], default="off",
                    help="Clock deskew between TX/RX: 'ls'=least-squares fit rx=a*tx+b; 'robust'=iterative outlier-trim LS; 'off'=disabled")
    ap.add_argument("--deskew-thresh-ms", type=float, default=100.0,
                    help="Robust deskew residual threshold (ms) for trimming outliers per iteration (default: 100 ms)")
    ap.add_argument("--deskew-iters", type=int, default=2,
                    help="Robust deskew iterations (default: 2)")
    return ap.parse_args()

def parse_label_file(arg: str) -> Tuple[str, str]:
    if ":" not in arg:
        print(f"Input '{arg}' must be in Label:filename format", file=sys.stderr)
        sys.exit(2)
    label, fn = arg.split(":", 1)
    return label, fn

def parse_iperf3_json(fn: str) -> Tuple[np.ndarray, Optional[float]]:
    with open(fn, "r") as f:
        data = json.load(f)
    rates = [iv["sum"]["bits_per_second"] / 1e6 for iv in data.get("intervals", [])]
    rates = np.asarray(rates, dtype=float)
    loss_pct = None
    try:
        end = data.get("end", {})
        if "sum" in end and "lost_percent" in end["sum"]:
            loss_pct = float(end["sum"]["lost_percent"])
        else:
            streams = end.get("streams", [])
            for s in streams:
                if "udp" in s and "lost_percent" in s["udp"]:
                    loss_pct = float(s["udp"]["lost_percent"])
                    break
    except Exception:
        pass
    return rates, loss_pct

# ---------- Robust PCAP field extraction ----------

def tshark_fields_proto(fn: str, bpf: str, disp: str, fields: List[str]) -> List[List[str]]:
    """
    disp: display filter (e.g., 'udp', 'tcp', 'ip', or '' for none)
    fields: list of field names to extract
    """
    if not has_tshark():
        print("ERROR: tshark not found in PATH; required for PCAP parsing.", file=sys.stderr)
        sys.exit(3)
    cmd = ["tshark", "-r", fn, "-T", "fields", "-E", "separator=,"]
    for f in fields:
        cmd += ["-e", f]
    # Display filter logic
    if disp:
        flt = disp if not bpf else f"({disp}) and ({bpf})"
        cmd += ["-Y", flt]
    elif bpf:
        cmd += ["-Y", bpf]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        err = (out.stderr or "").strip().splitlines()
        msg = err[-1] if err else "unknown tshark error"
        print(f"[ERROR] tshark failed for {os.path.basename(fn)}: {msg}")
        return []
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    rows = [ln.split(",") for ln in lines if "," in ln]
    return rows

def tshark_fields(fn: str, bpf: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Return (timestamps, payload_lengths_bytes) with robust fallbacks:
      1) udp.length (display filter: udp)
      2) tcp.len    (display filter: tcp)
      3) ip.len     (display filter: ip)        -> treat as bytes
      4) frame.len  (no proto filter; uses bpf) -> treat as bytes
    """
    # 1) UDP payload bytes
    rows = tshark_fields_proto(fn, bpf, "udp", ["frame.time_epoch", "udp.length"])
    used = "udp.length"
    # 2) TCP payload bytes
    if not rows:
        rows = tshark_fields_proto(fn, bpf, "tcp", ["frame.time_epoch", "tcp.len"])
        used = "tcp.len"
    # 3) IP total length (bytes)
    if not rows:
        rows = tshark_fields_proto(fn, bpf, "ip", ["frame.time_epoch", "ip.len"])
        used = "ip.len"
    # 4) Frame length (bytes)
    if not rows:
        rows = tshark_fields_proto(fn, bpf, "", ["frame.time_epoch", "frame.len"])
        used = "frame.len"

    if not rows:
        return np.array([]), np.array([])

    ts, ln_bytes = [], []
    for r in rows:
        try:
            ts.append(float(r[0]))
            ln_bytes.append(int(r[1]))
        except Exception:
            continue
    ts_arr = np.asarray(ts, dtype=float)
    len_arr = np.asarray(ln_bytes, dtype=float)

    if ts_arr.size == 0:
        return np.array([]), np.array([])
    # Debug訊息（必要時開）
    # print(f"[DBG] Using field: {used}, samples={ts_arr.size}")
    return ts_arr, len_arr

# ---------- Latency helpers (IPv4/UDP by ip.id + udp.length) ----------

# ---------- Stats & plotting ----------

def bin_throughput(ts: np.ndarray, lengths: np.ndarray, bin_sec: float) -> np.ndarray:
    if ts.size == 0: return np.array([])
    t0, t1 = ts.min(), ts.max()
    bins = max(1, int(math.ceil((t1 - t0) / bin_sec)))
    edges = np.linspace(t0, t0 + bins * bin_sec, bins + 1)
    bytes_per_bin, _ = np.histogram(ts, bins=edges, weights=lengths)
    return (bytes_per_bin * 8) / (bin_sec * 1e6)  # Mbps

def compute_jitter_ms(ts: np.ndarray) -> np.ndarray:
    if ts.size < 3: return np.array([])
    deltas = np.diff(ts)
    median_delta = np.median(deltas)
    absD_ms = np.abs(deltas - median_delta) * 1000.0
    return np.sort(absD_ms)

def smooth_series(arr: np.ndarray, win: int) -> np.ndarray:
    if win <= 1 or arr.size == 0: return arr
    win = min(win, len(arr))
    cumsum = np.cumsum(np.insert(arr, 0, 0.0))
    sm = (cumsum[win:] - cumsum[:-win]) / float(win)
    pad_left = np.full(win - 1, sm[0] if sm.size > 0 else 0.0)
    return np.concatenate([pad_left, sm]) if sm.size > 0 else arr

def load_series(label: str, fn: str, bin_sec: float, bpf: str) -> Series:
    ext = os.path.splitext(fn)[1].lower()
    if ext == ".json":
        rates, loss_pct = parse_iperf3_json(fn)
        rate_ts = rates
        rate_samples = np.sort(rates)
        return Series(label, rate_ts, rate_samples, None,
                      float(np.mean(rates)) if rates.size else None,
                      float(np.percentile(rates, 50)) if rates.size else None,
                      float(np.percentile(rates, 95)) if rates.size else None,
                      loss_pct)
    elif ext in SUPPORTED_PCAP_EXT:
        ts, lengths = tshark_fields(fn, bpf)
        if ts.size == 0:
            rate_ts = np.array([]); jitter_samples = np.array([])
        else:
            order = np.argsort(ts); ts = ts[order]; lengths = lengths[order]
            rate_ts = bin_throughput(ts, lengths, bin_sec)
            jitter_samples = compute_jitter_ms(ts)
        rate_samples = np.sort(rate_ts[rate_ts > 0]) if rate_ts.size else np.array([])
        return Series(label, rate_ts, rate_samples, jitter_samples,
                      float(np.mean(rate_ts)) if rate_ts.size else None,
                      float(np.percentile(rate_ts, 50)) if rate_ts.size else None,
                      float(np.percentile(rate_ts, 95)) if rate_ts.size else None,
                      None)
    else:
        print(f"Unsupported file type for {fn}", file=sys.stderr); sys.exit(6)

def ensure_outdir(path: str):
    os.makedirs(path, exist_ok=True)

def annotate_means_header(fig, series_list: List[Series]):
    lines = []
    for s in series_list:
        if s.mean_rate_mbps is not None:
            lines.append(f"{s.label}: mean {s.mean_rate_mbps:.2f} Mbps")
    if not lines:
        return
    txt = "\n".join(lines)
    fig.text(0.01, 0.98, txt, ha="left", va="top",
             fontsize=9, bbox=dict(boxstyle="round", alpha=0.15, lw=0.5))

def plot_timeseries(series_list: List[Series], prefix: str, outdir: str, smooth_win: int, bin_sec: float, annotate: bool):
    fig, ax = plt.subplots()
    plotted = False
    for s in series_list:
        y = s.rate_ts
        if y is None or y.size == 0: continue
        if smooth_win and smooth_win > 1: y = smooth_series(y, smooth_win)
        x = np.arange(len(y)) * bin_sec
        ax.plot(x, y, label=s.label)
        plotted = True
    ax.set_xlabel(f"Time (s)  [bin={bin_sec:.3f}s]")
    ax.set_ylabel("Throughput (Mbps)")
    ax.set_title("Throughput Time Series")
    if plotted: ax.legend()
    ax.grid(True); fig.tight_layout(rect=[0,0,1,0.93])
    if annotate: annotate_means_header(fig, series_list)
    out = os.path.join(outdir, f"{prefix}_throughput_timeseries.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}")

def plot_cdf(series_list: List[Series], prefix: str, outdir: str, annotate: bool):
    fig, ax = plt.subplots()
    plotted = False
    for s in series_list:
        data = s.rate_samples
        if data is None or data.size == 0: continue
        cdf = np.arange(1, len(data) + 1) / len(data)
        ax.plot(data, cdf, label=s.label)
        plotted = True
    ax.set_xlabel("Throughput (Mbps)")
    ax.set_ylabel("CDF")
    ax.set_title("Throughput CDF")
    if plotted: ax.legend()
    ax.grid(True); fig.tight_layout(rect=[0,0,1,0.93])
    if annotate: annotate_means_header(fig, series_list)
    out = os.path.join(outdir, f"{prefix}_throughput_cdf.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}")

def plot_jitter_cdf(series_list: List[Series], prefix: str, outdir: str):
    fig, ax = plt.subplots()
    plotted = False
    for s in series_list:
        js = s.jitter_ms_samples
        if js is None or js.size == 0: continue
        cdf = np.arange(1, len(js) + 1) / len(js)
        ax.plot(js, cdf, label=s.label)
        plotted = True
    if not plotted:
        plt.close(fig)
        print("[INFO] No jitter data (PCAPs) to plot."); return
    ax.set_xlabel("Instantaneous jitter |D| (ms)")
    ax.set_ylabel("CDF")
    ax.set_title("Receiver-side Jitter CDF (arrival-based)")
    ax.legend(); ax.grid(True); fig.tight_layout()
    out = os.path.join(outdir, f"{prefix}_jitter_cdf.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}")

# ---------- Latency (single / multiple) ----------

def tshark_latency_keyed(fn: str, bpf: str) -> Dict[Tuple[int,int], List[float]]:
    rows = tshark_fields_proto(fn, bpf, "udp", ["frame.time_epoch", "ip.id", "udp.length"])
    d: Dict[Tuple[int,int], List[float]] = {}
    for r in rows:
        try:
            t = float(r[0]); ipid = int(r[1]); ln = int(r[2])
            d.setdefault((ipid, ln), []).append(t)
        except Exception:
            continue
    return d

def tshark_latency_keyed_tuple(fn: str, bpf: str) -> Dict[Tuple[str,str,str,str,int], List[float]]:
    """Return mapping keyed by (src,dst,sport,dport,udp.length) supporting IPv4/IPv6.
    Uses fields: ip.src/ip.dst and ipv6.src/ipv6.dst; chooses whichever is present per row.
    """
    rows = tshark_fields_proto(
        fn, bpf, "udp",
        [
            "frame.time_epoch",
            "ip.src", "ip.dst",
            "ipv6.src", "ipv6.dst",
            "udp.srcport", "udp.dstport",
            "udp.length",
        ],
    )
    d: Dict[Tuple[str,str,str,str,int], List[float]] = {}
    for r in rows:
        try:
            t = float(r[0])
            ip4_src = r[1].strip()
            ip4_dst = r[2].strip()
            ip6_src = r[3].strip()
            ip6_dst = r[4].strip()
            sport = r[5].strip()
            dport = r[6].strip()
            ln = int(r[7])
            src = ip4_src if ip4_src else ip6_src
            dst = ip4_dst if ip4_dst else ip6_dst
            if not src or not dst or not sport or not dport:
                continue
            key = (src, dst, sport, dport, ln)
            d.setdefault(key, []).append(t)
        except Exception:
            continue
    return d

def tshark_latency_keyed_ports(fn: str, bpf: str) -> Dict[Tuple[str,str,int], List[float]]:
    """Return mapping keyed by (sport,dport,udp.length), ignoring IP addresses. Useful when NAT changes IPs.
    """
    rows = tshark_fields_proto(
        fn, bpf, "udp",
        [
            "frame.time_epoch",
            "udp.srcport", "udp.dstport",
            "udp.length",
        ],
    )
    d: Dict[Tuple[str,str,int], List[float]] = {}
    for r in rows:
        try:
            t = float(r[0])
            sport = r[1].strip(); dport = r[2].strip(); ln = int(r[3])
            if not sport or not dport:
                continue
            key = (sport, dport, ln)
            d.setdefault(key, []).append(t)
        except Exception:
            continue
    return d

def tshark_latency_keyed_iperf3(fn: str, bpf: str) -> Dict[int, List[float]]:
    """Return mapping from iperf3 UDP sequence number -> list of times.
    iperf3 UDP payload layout (first 12 bytes):
      - 32-bit sequence number (big-endian signed)
      - 32-bit tv_sec (big-endian)
      - 32-bit tv_usec (big-endian)
    We parse udp.payload as hex and read the first 4 bytes.
    """
    # Prefer data.data (payload hex) for compatibility; fallback to udp.payload if needed
    rows = tshark_fields_proto(fn, bpf, "udp", ["frame.time_epoch", "data.data"])
    if not rows:
        rows = tshark_fields_proto(fn, bpf, "udp", ["frame.time_epoch", "udp.payload"])
    d: Dict[int, List[float]] = {}
    for r in rows:
        try:
            t = float(r[0]); hexpayload = (r[1] or "").replace(":", "").strip()
            if len(hexpayload) < 8:
                continue
            seq_bytes = bytes.fromhex(hexpayload[:8])
            # iperf3 uses signed 32-bit, but for matching signed/unsigned are equivalent for equality
            seq = int.from_bytes(seq_bytes, byteorder='big', signed=True)
            d.setdefault(seq, []).append(t)
        except Exception:
            continue
    return d

def _pair_delays(tx_times: List[float], rx_times: List[float], mode: str, bound_ms: float, max_gap_ms: float) -> List[float]:
    delays: List[float] = []
    if not tx_times or not rx_times:
        return delays
    if mode == "seq":
        cnt = min(len(tx_times), len(rx_times))
        for i in range(cnt):
            d = (rx_times[i] - tx_times[i]) * 1000.0
            if bound_ms is None or bound_ms <= 0 or (-bound_ms <= d <= bound_ms):
                delays.append(d)
        return delays
    # nearest neighbor, monotonic greedy (tolerates losses/reorder)
    j = 0
    max_gap_s = max(0.0, (max_gap_ms if max_gap_ms is not None else 0.0) / 1000.0)
    for ti in tx_times:
        # advance rx pointer to first rx >= ti - max_gap
        while j < len(rx_times) and rx_times[j] < ti - max_gap_s:
            j += 1
        if j >= len(rx_times):
            break
        # scan candidates within [ti - max_gap, ti + max_gap], pick closest to ti (prefer rx>=ti)
        best_k = -1
        best_diff = None
        k = j
        while k < len(rx_times) and rx_times[k] <= ti + max_gap_s:
            diff = rx_times[k] - ti
            ad = abs(diff)
            if (best_diff is None) or (ad < best_diff) or (ad == best_diff and diff >= 0 and (rx_times[best_k] - ti) < 0):
                best_diff = ad
                best_k = k
            k += 1
        if best_k == -1:
            continue
        d = (rx_times[best_k] - ti) * 1000.0
        if bound_ms is None or bound_ms <= 0 or (-bound_ms <= d <= bound_ms):
            delays.append(d)
        # move j past the chosen rx to keep monotonic mapping
        j = best_k + 1
    return delays

def _collect_pairs_by_key(tx_map, rx_map, match_mode: str, bound_ms: float, max_gap_ms: float) -> Tuple[List[float], List[float]]:
    tx_all: List[float] = []
    rx_all: List[float] = []
    for key, tx_times in tx_map.items():
        rxs = rx_map.get(key, [])
        if not rxs:
            continue
        tx_sorted = sorted(tx_times)
        rx_sorted = sorted(rxs)
        if match_mode == "seq":
            cnt = min(len(tx_sorted), len(rx_sorted))
            for i in range(cnt):
                tx_all.append(tx_sorted[i]); rx_all.append(rx_sorted[i])
        else:
            # nearest: build delays then reconstruct pairs
            j = 0
            max_gap_s = max(0.0, (max_gap_ms if max_gap_ms is not None else 0.0) / 1000.0)
            for ti in tx_sorted:
                while j < len(rx_sorted) and rx_sorted[j] < ti - max_gap_s:
                    j += 1
                if j >= len(rx_sorted):
                    break
                best_k = -1; best_diff = None; k = j
                while k < len(rx_sorted) and rx_sorted[k] <= ti + max_gap_s:
                    diff = rx_sorted[k] - ti; ad = abs(diff)
                    if (best_diff is None) or (ad < best_diff) or (ad == best_diff and diff >= 0):
                        best_diff = ad; best_k = k
                    k += 1
                if best_k == -1:
                    continue
                tx_all.append(ti); rx_all.append(rx_sorted[best_k])
                j = best_k + 1
    # optional pre-bound filter on raw diffs
    if bound_ms is not None and bound_ms > 0 and tx_all:
        keep_tx = []; keep_rx = []
        for tx, rx in zip(tx_all, rx_all):
            d = (rx - tx) * 1000.0
            if -bound_ms <= d <= bound_ms:
                keep_tx.append(tx); keep_rx.append(rx)
        tx_all, rx_all = keep_tx, keep_rx
    return tx_all, rx_all

def _deskew_fit(tx: np.ndarray, rx: np.ndarray, mode: str, thresh_ms: float, iters: int) -> Tuple[float, float, np.ndarray]:
    # returns (a, b, inlier_mask)
    if tx.size == 0:
        return 1.0, 0.0, np.ones(0, dtype=bool)
    a, b = np.polyfit(tx, rx, 1)
    mask = np.ones_like(tx, dtype=bool)
    if mode == "robust":
        for _ in range(max(1, iters)):
            pred = a * tx + b
            resid = rx - pred
            thr = (thresh_ms if thresh_ms is not None else 100.0) / 1000.0
            new_mask = np.abs(resid) <= thr
            if new_mask.sum() < max(3, int(0.5 * len(tx))):
                # avoid collapsing too much
                break
            if np.all(new_mask == mask):
                break
            mask = new_mask
            a, b = np.polyfit(tx[mask], rx[mask], 1)
    return a, b, mask

def latency_from_pair(tx_pcap: str, rx_pcap: str, bpf: str, align: str = "none", key_mode: str = "ipidlen", bound_ms: float = 10000.0, match_mode: str = "seq", max_gap_ms: float = 200.0, deskew_mode: str = "off", deskew_thresh_ms: float = 100.0, deskew_iters: int = 2) -> np.ndarray:
    # Primary mapping based on requested key
    if key_mode == "tuple":
        tx_map = tshark_latency_keyed_tuple(tx_pcap, bpf)
        rx_map = tshark_latency_keyed_tuple(rx_pcap, bpf)
    elif key_mode == "ports":
        tx_map = tshark_latency_keyed_ports(tx_pcap, bpf)
        rx_map = tshark_latency_keyed_ports(rx_pcap, bpf)
    elif key_mode == "iperf3":
        tx_map = tshark_latency_keyed_iperf3(tx_pcap, bpf)
        rx_map = tshark_latency_keyed_iperf3(rx_pcap, bpf)
    else:
        tx_map = tshark_latency_keyed(tx_pcap, bpf)
        rx_map = tshark_latency_keyed(rx_pcap, bpf)
    if not tx_map:
        print(f"[WARN] No TX packets parsed from {os.path.basename(tx_pcap)} (bpf='{bpf}', key={key_mode}).")
    if not rx_map:
        print(f"[WARN] No RX packets parsed from {os.path.basename(rx_pcap)} (bpf='{bpf}', key={key_mode}).")
    # If iperf3 key: pair by exact sequence number intersection for best accuracy
    if key_mode == "iperf3":
        # collapse to earliest timestamp per seq to avoid duplicates
        tx_seq = {seq: min(ts) for seq, ts in tx_map.items() if ts}
        rx_seq = {seq: min(ts) for seq, ts in rx_map.items() if ts}
        common = sorted(set(tx_seq.keys()) & set(rx_seq.keys()))
        if not common:
            return np.array([])
        tx_all = np.array([tx_seq[s] for s in common], dtype=float)
        rx_all = np.array([rx_seq[s] for s in common], dtype=float)
        # Optional pre-bound filter
        if bound_ms is not None and bound_ms > 0:
            diffs = (rx_all - tx_all) * 1000.0
            mask = (diffs >= -bound_ms) & (diffs <= bound_ms)
            tx_all = tx_all[mask]; rx_all = rx_all[mask]
        # Deskew
        if deskew_mode != "off":
            a, b, mask = _deskew_fit(tx_all, rx_all, deskew_mode, deskew_thresh_ms, deskew_iters)
            if mask.size and mask.sum() < mask.size:
                tx_all = tx_all[mask]; rx_all = rx_all[mask]
            delays = (rx_all - (a * tx_all + b)) * 1000.0
            # After deskew, optional align to min/median for display
            if delays.size:
                if align == "min":
                    delays = delays - np.min(delays)
                elif align == "median":
                    delays = delays - np.median(delays)
            return np.sort(delays)
        else:
            # No deskew: raw diffs + align
            delays = (rx_all - tx_all) * 1000.0
            if delays.size:
                if align == "min": delays = delays - np.min(delays)
                elif align == "median": delays = delays - np.median(delays)
            return np.sort(delays)
    # Other keys: collect pairs per key using chosen pairing mode
    tx_list, rx_list = _collect_pairs_by_key(tx_map, rx_map, match_mode, bound_ms, max_gap_ms)
    if not tx_list:
        # Fallbacks for non-iperf3 keys
        if key_mode == "ipidlen":
            tx_map = tshark_latency_keyed_tuple(tx_pcap, bpf)
            rx_map = tshark_latency_keyed_tuple(rx_pcap, bpf)
            tx_list, rx_list = _collect_pairs_by_key(tx_map, rx_map, match_mode, bound_ms, max_gap_ms)
            if tx_list:
                print("[INFO] Fallback to tuple matching (src,dst,sport,dport,len).")
        if not tx_list:
            tx_map = tshark_latency_keyed_ports(tx_pcap, bpf)
            rx_map = tshark_latency_keyed_ports(rx_pcap, bpf)
            tx_list, rx_list = _collect_pairs_by_key(tx_map, rx_map, match_mode, bound_ms, max_gap_ms)
            if tx_list:
                print("[INFO] Fallback to ports matching (sport,dport,len).")
    if not tx_list:
        return np.array([])
    tx_all = np.asarray(tx_list, dtype=float)
    rx_all = np.asarray(rx_list, dtype=float)
    # Optional deskew for other keys as well
    if deskew_mode != "off":
        a, b, mask = _deskew_fit(tx_all, rx_all, deskew_mode, deskew_thresh_ms, deskew_iters)
        if mask.size and mask.sum() < mask.size:
            tx_all = tx_all[mask]; rx_all = rx_all[mask]
        delays = (rx_all - (a * tx_all + b)) * 1000.0
    else:
        delays = (rx_all - tx_all) * 1000.0
    if delays.size:
        if align == "min": delays = delays - np.min(delays)
        elif align == "median": delays = delays - np.median(delays)
    return np.sort(delays)
    # Fallback: progressively try more tolerant keys
    if not delays_ms and key_mode == "ipidlen":
        tx_map = tshark_latency_keyed_tuple(tx_pcap, bpf)
        rx_map = tshark_latency_keyed_tuple(rx_pcap, bpf)
        for key, tx_times in tx_map.items():
            rxs = rx_map.get(key, [])
            if not rxs: continue
            tx_sorted = sorted(tx_times)
            rx_sorted = sorted(rxs)
            delays_ms.extend(_pair_delays(tx_sorted, rx_sorted, match_mode, bound_ms, max_gap_ms))
        if delays_ms:
            print("[INFO] Fallback to tuple matching (src,dst,sport,dport,len).")
    if not delays_ms and key_mode in ("ipidlen", "tuple"):
        tx_map = tshark_latency_keyed_ports(tx_pcap, bpf)
        rx_map = tshark_latency_keyed_ports(rx_pcap, bpf)
        for key, tx_times in tx_map.items():
            rxs = rx_map.get(key, [])
            if not rxs: continue
            tx_sorted = sorted(tx_times)
            rx_sorted = sorted(rxs)
            delays_ms.extend(_pair_delays(tx_sorted, rx_sorted, match_mode, bound_ms, max_gap_ms))
        if delays_ms:
            print("[INFO] Fallback to ports matching (sport,dport,len).")
    if not delays_ms:
        return np.array([])
    arr = np.asarray(delays_ms, dtype=float)
    if align == "min":
        arr = arr - np.min(arr)
    elif align == "median":
        arr = arr - np.median(arr)
    return np.sort(arr)

def latency_cdf_single(prefix: str, outdir: str, tx_pcap: str, rx_pcap: str, bpf: str, align: str = "none", csv_path: str = "", key_mode: str = "ipidlen", bound_ms: float = 10000.0, match_mode: str = "seq", max_gap_ms: float = 200.0, deskew_mode: str = "off", deskew_thresh_ms: float = 100.0, deskew_iters: int = 2):
    data = latency_from_pair(tx_pcap, rx_pcap, bpf, align, key_mode, bound_ms, match_mode, max_gap_ms, deskew_mode, deskew_thresh_ms, deskew_iters)
    if data.size == 0:
        print("[WARN] No matched packets for latency (single)."); return
    cdf = np.arange(1, len(data) + 1) / len(data)
    fig, ax = plt.subplots()
    ax.plot(data, cdf)
    ax.set_xlabel(f"One-way delay (ms) [key={key_mode}, align={align}, match={match_mode}, deskew={deskew_mode}]")
    ax.set_ylabel("CDF")
    ax.set_title("Latency CDF (paired PCAPs)")
    ax.grid(True); fig.tight_layout()
    out = os.path.join(outdir, f"{prefix}_latency_cdf.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}  (N={len(data)})")
    # Optional CSV export
    if csv_path:
        header_needed = not os.path.exists(csv_path)
        with open(csv_path, "a") as f:
            if header_needed:
                f.write("delay_ms\n")
            for v in data:
                f.write(f"{v:.6f}\n")
        print(f"[OK] Wrote CSV: {csv_path} (single)")

def latency_cdf_multi(prefix: str, outdir: str, items: List[Tuple[str,str,str]], bpf: str, align: str = "none", csv_path: str = "", key_mode: str = "ipidlen", bound_ms: float = 10000.0, match_mode: str = "seq", max_gap_ms: float = 200.0, deskew_mode: str = "off", deskew_thresh_ms: float = 100.0, deskew_iters: int = 2):
    fig, ax = plt.subplots()
    plotted = False
    csv_header_written = False
    if csv_path and os.path.exists(csv_path):
        # If file already exists, assume it may already have a header
        try:
            with open(csv_path, 'r') as f:
                first = f.readline().strip()
                if first == 'label,delay_ms':
                    csv_header_written = True
        except Exception:
            pass
    for label, tx_pcap, rx_pcap in items:
        data = latency_from_pair(tx_pcap, rx_pcap, bpf, align, key_mode, bound_ms, match_mode, max_gap_ms, deskew_mode, deskew_thresh_ms, deskew_iters)
        if data.size == 0:
            print(f"[WARN] {label}: no matched packets for latency.")
            continue
        cdf = np.arange(1, len(data) + 1) / len(data)
        ax.plot(data, cdf, label=label)
        p50 = np.percentile(data, 50)
        p90 = np.percentile(data, 90)
        p99 = np.percentile(data, 99)
        print(f"[LAT] {label:12s}  N={len(data):6d}  p50={p50:7.3f} ms  p90={p90:7.3f} ms  p99={p99:7.3f} ms")
        # Optional CSV export (append with label)
        if csv_path:
            if not csv_header_written:
                with open(csv_path, "w") as f:
                    f.write("label,delay_ms\n")
                csv_header_written = True
            with open(csv_path, "a") as f:
                for v in data:
                    f.write(f"{label},{v:.6f}\n")
        plotted = True
    if not plotted:
        plt.close(fig)
        print("[WARN] No latency lines plotted."); return
    ax.set_xlabel(f"One-way delay (ms) [key={key_mode}, align={align}, match={match_mode}, deskew={deskew_mode}]")
    ax.set_ylabel("CDF")
    ax.set_title("Latency CDF (multiple flows)")
    ax.legend(); ax.grid(True); fig.tight_layout()
    out = os.path.join(outdir, f"{prefix}_latency_cdf.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}")

def parse_latpairs(args) -> List[Tuple[str,str,str]]:
    items = []
    for token in args.latpairs:
        try:
            parts = [p.strip() for p in token.split(",")]
            label = parts[0]
            tx = next(p[3:] for p in parts if p.startswith("tx:"))
            rx = next(p[3:] for p in parts if p.startswith("rx:"))
            items.append((label, tx, rx))
        except Exception:
            print(f"[WARN] Bad --latpairs item: {token}")
    return items

def print_summary(series_list: List[Series]):
    print("\n=== Summary ===")
    for s in series_list:
        mean = f"{s.mean_rate_mbps:.2f} Mbps" if s.mean_rate_mbps is not None else "-"
        p50 = f"{s.p50_rate_mbps:.2f} Mbps" if s.p50_rate_mbps is not None else "-"
        p95 = f"{s.p95_rate_mbps:.2f} Mbps" if s.p95_rate_mbps is not None else "-"
        loss = f"{s.loss_pct:.3f} %%" if s.loss_pct is not None else "-"
        print(f"{s.label:20s}  mean={mean:>12s}  p50={p50:>12s}  p95={p95:>12s}  UDP loss={loss}")

def main():
    args = parse_args()
    ensure_outdir(args.outdir)

    # throughput/jitter from inputs (optional)
    if args.inputs:
        series_list: List[Series] = []
        for arg in args.inputs:
            label, fn = parse_label_file(arg)
            s = load_series(label, fn, args.bin, args.bpf)
            series_list.append(s)
        plot_timeseries(series_list, args.prefix, args.outdir, args.smooth, args.bin, args.annotate_means)
        plot_cdf(series_list, args.prefix, args.outdir, args.annotate_means)
        plot_jitter_cdf(series_list, args.prefix, args.outdir)
        print_summary(series_list)
    else:
        print("[INFO] No throughput inputs provided; running in latency-only mode.")

    # latency: single pair
    if args.latpair:
        tx = rx = None
        for token in args.latpair:
            if token.startswith("tx:"): tx = token[3:]
            elif token.startswith("rx:"): rx = token[3:]
        if tx and rx:
            latency_cdf_single(
                args.prefix, args.outdir, tx, rx,
                args.bpf_lat, args.lat_align, args.lat_csv,
                args.lat_key, args.lat_bound_ms, args.lat_match, args.lat_max_gap_ms,
                args.deskew, args.deskew_thresh_ms, args.deskew_iters
            )
        else:
            print("[WARN] --latpair needs both tx:<pcap> and rx:<pcap>")

    # latency: multiple pairs one figure
    items = parse_latpairs(args)
    if items:
        latency_cdf_multi(
            args.prefix, args.outdir, items,
            args.bpf_lat, args.lat_align, args.lat_csv,
            args.lat_key, args.lat_bound_ms, args.lat_match, args.lat_max_gap_ms,
            args.deskew, args.deskew_thresh_ms, args.deskew_iters
        )

if __name__ == "__main__":
    main()
