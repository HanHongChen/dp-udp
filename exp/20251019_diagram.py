
# --- Imports ---
import numpy as np
import matplotlib.pyplot as plt
import argparse
import json
import math
import os
import shutil
import subprocess
import sys
from typing import List, Tuple, Optional, Dict

SUPPORTED_PCAP_EXT = (".pcap", ".pcapng", ".cap")

class Series:
    def __init__(self, label, rate_ts, rate_samples, jitter_ms_samples=None, mean_rate_mbps=None, p50_rate_mbps=None, p95_rate_mbps=None, loss_pct=None):
        self.label = label
        self.rate_ts = rate_ts
        self.rate_samples = rate_samples
        self.jitter_ms_samples = jitter_ms_samples
        self.mean_rate_mbps = mean_rate_mbps
        self.p50_rate_mbps = p50_rate_mbps
        self.p95_rate_mbps = p95_rate_mbps
        self.loss_pct = loss_pct

def has_tshark():
    return shutil.which("tshark") is not None

def parse_label_file(arg: str) -> Tuple[str, str]:
    if ":" not in arg:
        print(f"Input '{arg}' must be in Label:filename format", file=sys.stderr)
        sys.exit(2)
    label, fn = arg.split(":", 1)
    return label, fn

def tshark_fields_proto(fn: str, bpf: str, disp: str, fields: List[str]) -> List[List[str]]:
    if not has_tshark():
        print("ERROR: tshark not found in PATH; required for PCAP parsing.", file=sys.stderr)
        sys.exit(3)

    # 先放 -T fields / -n；**一定要先把 -e 欄位加進去**，最後才加 -E
    cmd = ["tshark", "-r", fn, "-T", "fields", "-n"]

    # 欄位（很重要：確保真的有帶 -e）
    for f in fields:
        cmd += ["-e", f]

    # 顯示濾器：disp（協定層）與 bpf 以 AND 合併；或只有 bpf
    if disp:
        flt = disp if not bpf else f"({disp}) and ({bpf})"
        cmd += ["-Y", flt]
    elif bpf:
        cmd += ["-Y", bpf]

    # -E 一律用 key=value 寫法，放在最後
    cmd += ["-E", "separator=,", "-E", "occurrence=f"]

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
    rows = tshark_fields_proto(fn, bpf, "udp", ["frame.time_epoch", "udp.length"])
    used = "udp.length"
    if not rows:
        rows = tshark_fields_proto(fn, bpf, "tcp", ["frame.time_epoch", "tcp.len"])
        used = "tcp.len"
    if not rows:
        rows = tshark_fields_proto(fn, bpf, "ip", ["frame.time_epoch", "ip.len"])
        used = "ip.len"
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
    return ts_arr, len_arr

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

def load_series(label: str, fn: str, bin_sec: float, bpf: str) -> Series:
    ext = os.path.splitext(fn)[1].lower()
    if ext in SUPPORTED_PCAP_EXT:
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

def plot_timeseries_aligned(series_list: List[Series], prefix: str, outdir: str, smooth_win: int, bin_sec: float, annotate: bool, rate_thr_mbps: float):
    fig, ax = plt.subplots()
    plotted = False
    ymax = 0.0
    for s in series_list:
        y = s.rate_ts
        if y is None or y.size == 0: continue
        if smooth_win and smooth_win > 1: y = smooth_series(y, smooth_win)
        # Trim leading zeros/noise until throughput > threshold
        idx0 = 0
        thr = rate_thr_mbps if rate_thr_mbps is not None else 0.0
        for i, v in enumerate(y):
            if v > thr:
                idx0 = i
                break
        y = y[idx0:] if idx0 > 0 else y
        if y.size == 0: 
            continue
        # Align each series to its own start time (after trimming)
        x = np.arange(len(y)) * bin_sec
        ax.plot(x, y, label=s.label)
        ymax = max(ymax, np.max(y))

        plotted = True
    ax.set_xlabel(f"Time (s)  [bin={bin_sec:.3f}s]")
    ax.set_ylabel("Throughput (Mbps)")
    ax.set_title("Throughput Time Series (aligned to first non-zero)")
    if plotted: ax.legend()
    ax.grid(True); fig.tight_layout(rect=[0,0,1,0.93])
    if annotate: annotate_means_header(fig, series_list)
    if plotted and ymax > 0:
        ax.set_ylim(0, ymax * 1.5)  # 讓最高值再多出 30% 空間

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

def plot_jitter_cdf_scaled(series_list: List[Series], prefix: str, outdir: str, jitter_xmax_ms: float):
    fig, ax = plt.subplots()
    plotted = False
    all_jitter = []
    for s in series_list:
        js = s.jitter_ms_samples
        if js is None or js.size == 0: continue
        cdf = np.arange(1, len(js) + 1) / len(js)
        ax.plot(js, cdf, label=s.label)
        all_jitter.append(js)
        plotted = True
    if not plotted:
        plt.close(fig)
        print("[INFO] No jitter data (PCAPs) to plot."); return
    ax.set_xlabel("Instantaneous jitter |D| (ms)")
    ax.set_ylabel("CDF")
    ax.set_title("Receiver-side Jitter CDF (arrival-based)")
    ax.legend(); ax.grid(True); fig.tight_layout()
    # Axis scaling
    if all_jitter:
        all_jitter_flat = np.concatenate(all_jitter)
        if jitter_xmax_ms and jitter_xmax_ms > 0:
            ax.set_xlim(0, jitter_xmax_ms)
        else:
            max_jitter = max(10, np.percentile(all_jitter_flat, 99))
            ax.set_xlim(0, max_jitter)
    out = os.path.join(outdir, f"{prefix}_jitter_cdf.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}")

def smooth_series(arr: np.ndarray, win: int) -> np.ndarray:
    if win <= 1 or arr.size == 0: return arr
    win = min(win, len(arr))
    cumsum = np.cumsum(np.insert(arr, 0, 0.0))
    sm = (cumsum[win:] - cumsum[:-win]) / float(win)
    pad_left = np.full(win - 1, sm[0] if sm.size > 0 else 0.0)
    return np.concatenate([pad_left, sm]) if sm.size > 0 else arr

# --- Latency CDF (original ip.id + udp.length path) ---
def latency_from_pair(tx_pcap: str, rx_pcap: str, bpf: str) -> np.ndarray:
    # Use ip.id + udp.length as key
    def get_map(fn):
        rows = tshark_fields_proto(fn, bpf, "udp", ["frame.time_epoch", "ip.id", "udp.length"])
        d = {}
        for r in rows:
            try:
                t = float(r[0]); ipid = int(r[1]); ln = int(r[2])
                d.setdefault((ipid, ln), []).append(t)
            except Exception:
                continue
        return d
    tx_map = get_map(tx_pcap)
    rx_map = get_map(rx_pcap)
    delays = []
    for key, tx_times in tx_map.items():
        rxs = rx_map.get(key, [])
        if not rxs: continue
        tx_sorted = sorted(tx_times)
        rx_sorted = sorted(rxs)
        cnt = min(len(tx_sorted), len(rx_sorted))
        for i in range(cnt):
            d = (rx_sorted[i] - tx_sorted[i]) * 1000.0
            delays.append(d)
    arr = np.asarray(delays, dtype=float)
    return arr

def latency_cdf_multi_scaled(prefix, outdir, items, bpf):
    fig, ax = plt.subplots()
    plotted = False
    all_latency = []
    for label, tx_pcap, rx_pcap in items:
        data = latency_from_pair(tx_pcap, rx_pcap, bpf)
        if data.size == 0:
            print(f"[WARN] {label}: no matched packets for latency.")
            continue
        # Shift so min value is 0 (fix negative)
        data = data - np.min(data)
        cdf = np.arange(1, len(data) + 1) / len(data)
        ax.plot(data, cdf, label=label)
        all_latency.append(data)
        plotted = True
    if not plotted:
        plt.close(fig)
        print("[WARN] No latency lines plotted."); return
    ax.set_xlabel("One-way delay (ms) [key=ipidlen, align=min]")
    ax.set_ylabel("CDF")
    ax.set_title("Latency CDF (multiple flows)")
    ax.legend(); ax.grid(True); fig.tight_layout()
    # Auto scale x-axis to 99th percentile, min range 5ms
    if all_latency:
        all_latency_flat = np.concatenate(all_latency)
        min_lat = np.min(all_latency_flat)
        max_lat = np.percentile(all_latency_flat, 99)
        ax.set_xlim(min_lat, max(max_lat, min_lat + 5))
    out = os.path.join(outdir, f"{prefix}_latency_cdf.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}")

# --- Latency via iperf3 UDP sequence (NAT-safe) ---
def _iperf_seq_rows(fn: str, bpf: str, port: Optional[int]) -> Dict[int, List[float]]:
    # Extract iperf3 UDP payload (data.data) and parse first 4 bytes (big-endian) as seq
    disp = "udp"
    if port:
        disp = f"udp.port=={port}"
    flt = disp if not bpf else f"({disp}) and ({bpf})"
    rows = tshark_fields_proto(fn, bpf="", disp=flt, fields=["frame.time_epoch", "data.data"])
    seq_map: Dict[int, List[float]] = {}
    for r in rows:
        try:
            t = float(r[0])
            hexstr = r[1].replace(":", "").lower()
            if len(hexstr) < 8:
                continue
            seq = int(hexstr[0:8], 16)  # iperf3 UDP header: seq (32-bit BE)
            seq_map.setdefault(seq, []).append(t)
        except Exception:
            continue
    return seq_map

def latency_from_pair_iperf(tx_pcap: str, rx_pcap: str, bpf: str, port: Optional[int]) -> np.ndarray:
    tx = _iperf_seq_rows(tx_pcap, bpf, port)
    rx = _iperf_seq_rows(rx_pcap, bpf, port)
    delays = []
    for seq, tx_times in tx.items():
        rxs = rx.get(seq)
        if not rxs:
            continue
        # tx_sorted = sorted(tx_times)
        # rx_sorted = sorted(rxs)
        # n = min(len(tx_sorted), len(rx_sorted))
        # for i in range(n):
        #     d_ms = (rx_sorted[i] - tx_sorted[i]) * 1000.0
        #     delays.append(d_ms)
        t_tx = min(tx_times)
        t_rx = min(rxs)
        delays.append( (t_rx - t_tx) * 1000.0 )

    return np.asarray(delays, dtype=float)

def latency_cdf_multi_scaled_iperf(prefix, outdir, items, bpf, port, lat_xmax_ms):
    fig, ax = plt.subplots()
    plotted = False
    all_latency = []
    for label, tx_pcap, rx_pcap in items:
        data = latency_from_pair_iperf(tx_pcap, rx_pcap, bpf, port)
        if data.size == 0:
            print(f"[WARN] {label}: no matched iperf seq for latency.")
            continue
        # Align min to 0
        data = data - np.min(data)
        data = np.sort(data)
        cdf = np.arange(1, len(data) + 1) / len(data)
        ax.step(data, cdf, where="post", label=label)
        all_latency.append(data)
        plotted = True
    if not plotted:
        plt.close(fig)
        print("[WARN] No latency lines plotted.")
        return
    ax.set_xlabel("One-way delay (ms) [match=iperf seq, align=min]")
    ax.set_ylabel("CDF")
    ax.set_title("Latency CDF (multiple flows)")
    ax.legend(); ax.grid(True); fig.tight_layout()
    if all_latency:
        all_latency_flat = np.concatenate(all_latency)
        min_lat = max(0.0, np.min(all_latency_flat))
        max_lat = np.percentile(all_latency_flat, 99)
        # 修正：根據 lat_xmax_ms 決定 xlim
        if lat_xmax_ms and lat_xmax_ms > 0:
            ax.set_xlim(0, lat_xmax_ms)
        else:
            ax.set_xlim(min_lat, max(max_lat, min_lat + 5))
    out = os.path.join(outdir, f"{prefix}_latency_cdf.png")
    fig.savefig(out); plt.close(fig)
    print(f"[OK] Wrote {out}")
    # 99百分位/或手動上限
    all_latency_flat = np.concatenate(all_latency)
    if lat_xmax_ms and lat_xmax_ms > 0:
        ax.set_xlim(0, lat_xmax_ms)
    else:
        min_lat = max(0.0, np.min(all_latency_flat))
        max_lat = np.percentile(all_latency_flat, 99)
        ax.set_xlim(min_lat, max(max_lat, min_lat + 5))


def main():
    ap = argparse.ArgumentParser(description="Plot throughput/jitter/latency from PCAPs with improved axis scaling.")
    ap.add_argument("prefix", help="Output filename prefix")
    ap.add_argument("inputs", nargs="*", help="List like Label:file.pcap")
    ap.add_argument("--bpf", default="", help="BPF for throughput/jitter PCAPs")
    ap.add_argument("--bin", type=float, default=1.0, help="Bin size for throughput in seconds (default: 1.0)")
    ap.add_argument("--smooth", type=int, default=0, help="Rolling window for smoothing timeseries (0 = off)")
    ap.add_argument("--outdir", default=".", help="Output directory for figures")
    ap.add_argument("--annotate-means", action="store_true", help="Show per-series mean Mbps at top (multi-line)")
    ap.add_argument("--latpairs", nargs="*", default=[], help='Multiple pairs: "Label,tx:<pcap>,rx:<pcap>" ...')
    ap.add_argument("--bpf-lat", default="", help="BPF for latency pairs (applied to both tx/rx)")
    # NEW options
    ap.add_argument("--rate-threshold-mbps", type=float, default=0.0,
                    help="Trim leading bins until throughput > threshold (Mbps). Default 0 (no trim).")
    ap.add_argument("--jitter-xmax-ms", type=float, default=2.0,
                    help="Cap jitter CDF x-axis to this many milliseconds (default 2.0). Use 0 to auto-scale.")
    ap.add_argument("--lat-mode", choices=["ipidlen", "iperf"], default="iperf",
                    help="Latency matching mode: 'iperf' uses iperf3 UDP payload seq; 'ipidlen' uses (ip.id, udp.length). Default: iperf.")
    ap.add_argument("--lat-port", type=int, default=None,
                    help="UDP port for iperf latency matching. If not set, rely on --bpf-lat.")
    ap.add_argument("--lat-xmax-ms", type=float, default=0.0,
                help="Cap latency CDF x-axis to this many milliseconds (default 0 = auto-scale).")

    args = ap.parse_args()
    ensure_outdir(args.outdir)

    # Throughput/jitter
    series_list = []
    for arg in args.inputs:
        label, fn = parse_label_file(arg)
        s = load_series(label, fn, args.bin, args.bpf)
        series_list.append(s)
    if series_list:
        plot_timeseries_aligned(series_list, args.prefix, args.outdir, args.smooth, args.bin, args.annotate_means, args.rate_threshold_mbps)
        plot_cdf(series_list, args.prefix, args.outdir, args.annotate_means)
        plot_jitter_cdf_scaled(series_list, args.prefix, args.outdir, args.jitter_xmax_ms)

    # Latency: multiple pairs
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
    if items:
        if args.lat_mode == "iperf":
            latency_cdf_multi_scaled_iperf(args.prefix, args.outdir, items, args.bpf_lat, args.lat_port, args.lat_xmax_ms)
        else:
            latency_cdf_multi_scaled(args.prefix, args.outdir, items, args.bpf_lat)

if __name__ == "__main__":
    main()
