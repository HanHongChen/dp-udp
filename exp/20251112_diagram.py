
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
    average_delta = np.mean(deltas)
    # median_delta = np.median(deltas)
    absD_ms = np.abs(deltas - average_delta) * 1000.0
    return np.sort(absD_ms)

def load_series(label: str, fn: str, bin_sec: float, bpf: str) -> Series:
    ext = os.path.splitext(fn)[1].lower()
    if ext in SUPPORTED_PCAP_EXT:
        ts, lengths = tshark_fields(fn, bpf)
        if ts.size == 0:
            rate_ts = np.array([]); jitter_samples = np.array([])
        else:
            order = np.argsort(ts); ts = ts[order]; lengths = lengths[order]
            # 新：固定從 head_trim 秒後開始，保留 target_dur 秒（預設 10s 頭 + 60s 中段）
            head_trim = 10.0
            target_dur = 60.0
            t_start = ts.min() + head_trim
            t_end = t_start + target_dur

            # 若資料不足以覆蓋 t_end（例如 sender 比較早停止），退回到以 ts.max()-10 為結尾的備援策略
            if ts.max() < t_end:
                alt_end = ts.max() - head_trim
                if alt_end <= t_start:
                    # 資料太短，使用全部可用區間並警告
                    print(f"[WARN] {label}: not enough data to trim head/tail; available {ts.max()-ts.min():.3f}s. using full range.", file=sys.stderr)
                    t_start = ts.min()
                    t_end = ts.max()
                else:
                    t_end = alt_end

            m = (ts >= t_start) & (ts <= t_end)
            ts = ts[m]
            lengths = lengths[m]

            if ts.size == 0:
                rate_ts = np.array([]); jitter_samples = np.array([])
            else:
                # 重新歸零時間
                ts = ts - ts.min()
                rate_ts = bin_throughput(ts, lengths, bin_sec)
                jitter_samples = compute_jitter_ms(ts)

            # 印出 debug，檢查 trimming 後的長度與封包數
            trimmed_dur = (t_end - t_start) if (t_end and t_start) else 0.0
            print(f"[DEBUG] {label}: trimmed start={t_start:.3f}, end={t_end:.3f}, duration={trimmed_dur:.3f}s, packets_kept={len(ts)}", file=sys.stderr)

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

    # --- 自動抓 prefix 裡的流量資訊 (ex: "10M" or "5Mbps") ---
    import re
    m = re.search(r"(\d+\.?\d*)\s*(M|Mbps)", prefix, re.IGNORECASE)
    rate_label = f"{m.group(1)}M" if m else prefix

    for s in series_list:
        y = s.rate_ts
        if y is None or y.size == 0:
            continue
        if smooth_win and smooth_win > 1:
            y = smooth_series(y, smooth_win)

        # Trim leading zeros
        idx0 = next((i for i, v in enumerate(y) if v > rate_thr_mbps), 0)
        y = y[idx0:]
        if y.size == 0:
            continue

        x = np.arange(len(y)) * bin_sec
        ax.plot(x, y, label=s.label)
        ymax = max(ymax, np.max(y))
        plotted = True

    ax.set_xlabel("Time (sec)")
    ax.set_ylabel("Throughput (Mbps)")
    ax.set_title(f"Throughput: {rate_label}")
    if plotted:
        ax.legend()
        ax.grid(True)
        fig.tight_layout(rect=[0, 0, 1, 0.93])
        if annotate:
            annotate_means_header(fig, series_list)
        ax.set_ylim(0, ymax * 1.3)
        out = os.path.join(outdir, f"{prefix}_throughput_timeseries.png")
        fig.savefig(out)
        print(f"[OK] Wrote {out}")
    plt.close(fig)


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

    import re
    m = re.search(r"(\d+\.?\d*)\s*(M|Mbps)", prefix, re.IGNORECASE)
    rate_label = f"{m.group(1)}M" if m else prefix

    for s in series_list:
        js = s.jitter_ms_samples
        if js is None or js.size == 0:
            continue
        cdf = np.arange(1, len(js) + 1) / len(js)
        ax.plot(js, cdf, label=s.label)
        all_jitter.append(js)
        plotted = True

    if not plotted:
        plt.close(fig)
        print("[INFO] No jitter data (PCAPs) to plot.")
        return

    ax.set_xlabel("Inter-packet arrival variation (ms)")
    ax.set_ylabel("CDF")
    ax.set_title(f"Jitter: {rate_label}")
    ax.legend()
    ax.grid(True)
    fig.tight_layout()

    if all_jitter:
        all_jitter_flat = np.concatenate(all_jitter)
        if jitter_xmax_ms and jitter_xmax_ms > 0:
            xmax = jitter_xmax_ms
        else:
            xmax = np.percentile(all_jitter_flat, 99.9) * 1.2  # 自動放寬 20%
        ax.set_xlim(0, max(2.0, xmax))  # 最小至少 2ms

    out = os.path.join(outdir, f"{prefix}_jitter_cdf.png")
    fig.savefig(out)
    plt.close(fig)
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
    pairs = []
    for seq, tx_times in tx.items():
        rxs = rx.get(seq)
        if not rxs:
            continue
        t_tx = min(tx_times)
        t_rx = min(rxs)
        pairs.append((seq, t_tx, t_rx))
    if not pairs:
        return np.array([])

    pairs.sort(key=lambda x: x[0])
    tx_arr = np.array([p[1] for p in pairs])
    rx_arr = np.array([p[2] for p in pairs])

    # --- 動態偏移校正 ---
    seg_size = 50
    corrected_rx = np.zeros_like(rx_arr)
    total_segments = int(math.ceil(len(tx_arr) / seg_size))

    for i in range(total_segments):
        start = i * seg_size
        end = min((i + 1) * seg_size, len(tx_arr))
        tx_seg = tx_arr[start:end]
        rx_seg = rx_arr[start:end]

        if len(tx_seg) < 5:
            offset = np.median(rx_arr - tx_arr)  # 最後太少就用全域中位
        else:
            offset = np.median(rx_seg - tx_seg)
        corrected_rx[start:end] = rx_seg - offset

    # --- 計算修正後的 OWD ---
    owd_ms = (corrected_rx - tx_arr) * 1000.0
    owd_ms = owd_ms[(owd_ms >= 0) & (owd_ms < 1000)]

    print(f"[INFO] Latency computed ({len(owd_ms)} pkts, dynamic offset segments={total_segments})")
    return owd_ms

def latency_cdf_multi_scaled_iperf(prefix, outdir, items, bpf, port, lat_xmax_ms):
    fig, ax = plt.subplots()
    plotted = False
    all_latency = []

    import re
    m = re.search(r"(\d+\.?\d*)\s*(M|Mbps)", prefix, re.IGNORECASE)
    rate_label = f"{m.group(1)}M" if m else prefix

    for label, tx_pcap, rx_pcap in items:
        data = latency_from_pair_iperf(tx_pcap, rx_pcap, bpf, port)
        if data.size == 0:
            print(f"[WARN] {label}: no matched iperf seq for latency.")
            continue
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

    ax.set_xlabel("Delay (ms)")
    ax.set_ylabel("CDF")
    ax.set_title(f"Latency: {rate_label}")
    ax.legend()
    ax.grid(True)
    fig.tight_layout()

    if all_latency:
        all_latency_flat = np.concatenate(all_latency)
        if lat_xmax_ms and lat_xmax_ms > 0:
            xmax = lat_xmax_ms
        else:
            xmax = np.percentile(all_latency_flat, 99)
        ax.set_xlim(0, max(xmax, 5))

    out = os.path.join(outdir, f"{prefix}_latency_cdf.png")
    fig.savefig(out)
    plt.close(fig)
    print(f"[OK] Wrote {out}")

def _gather_latency_arrays(items, mode: str, bpf: str, port: Optional[int]):
    lat_arrays = []  # List[Tuple[label, np.ndarray]]
    for label, tx_pcap, rx_pcap in items:
        if mode == "iperf":
            data = latency_from_pair_iperf(tx_pcap, rx_pcap, bpf, port)
        else:
            data = latency_from_pair(tx_pcap, rx_pcap, bpf)
        if data.size == 0:
            print(f"[WARN] {label}: no latency samples for quantiles.")
            continue
        # 與 CDF 一樣：對齊最小值到 0，並排序
        data = data - np.min(data)
        data = np.sort(data)
        lat_arrays.append((label, data))
    return lat_arrays

def plot_latency_quantiles(prefix: str, outdir: str, lat_arrays):
    if not lat_arrays:
        print("[WARN] No latency arrays for p50/p95.")
        return

    labels, p50s, p95s = [], [], []
    for label, arr in lat_arrays:
        p50 = float(np.percentile(arr, 50))
        p95 = float(np.percentile(arr, 95))
        labels.append(label); p50s.append(p50); p95s.append(p95)
        print(f"[LAT] {label}: p50={p50:.3f} ms, p95={p95:.3f} ms")

    # 繪圖
    x = np.arange(len(labels))
    width = 0.35
    fig, ax = plt.subplots()
    b1 = ax.bar(x - width/2, p50s, width, label="p50")
    b2 = ax.bar(x + width/2, p95s, width, label="p95")

    ax.set_ylabel("Latency (ms)")
    ax.set_title("Latency quantiles (p50, p95)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    # 標註數值
    for bars in (b1, b2):
        for rect in bars:
            h = rect.get_height()
            ax.text(rect.get_x() + rect.get_width()/2, h, f"{h:.2f}",
                    ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    out_png = os.path.join(outdir, f"{prefix}_latency_p50_p95.png")
    fig.savefig(out_png); plt.close(fig)
    print(f"[OK] Wrote {out_png}")

    # 輸出 CSV
    out_csv = os.path.join(outdir, f"{prefix}_latency_p50_p95.csv")
    with open(out_csv, "w") as f:
        f.write("label,p50_ms,p95_ms\n")
        for lb, v50, v95 in zip(labels, p50s, p95s):
            f.write(f"{lb},{v50:.6f},{v95:.6f}\n")
    print(f"[OK] Wrote {out_csv}")


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
        # plot_cdf(series_list, args.prefix, args.outdir, args.annotate_means)
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

        # 新增：同時輸出 latency 的 p50/p95 長條圖與 CSV
        # lat_arrays = _gather_latency_arrays(items, args.lat_mode, args.bpf_lat, args.lat_port)
        # plot_latency_quantiles(args.prefix, args.outdir, lat_arrays)

if __name__ == "__main__":
    main()
