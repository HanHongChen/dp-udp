#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
from typing import List, Tuple, Optional
import numpy as np

# 新增：在無 X 環境也能輸出圖檔
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ---------- generic helpers ----------
def has_tshark() -> bool:
    return shutil.which("tshark") is not None

def _ensure_outdir(path: str):
    os.makedirs(path, exist_ok=True)

def _hex_to_bytes(hexstr: str) -> bytes:
    s = (hexstr or "").replace(":", "").strip()
    if not s:
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""

def _rows_fields(fn: str, disp: Optional[str], fields: List[str]) -> List[List[str]]:
    """
    Run tshark and return rows of selected fields.
    disp: Wireshark display filter (can be None/empty to skip)
    """
    if not has_tshark():
        raise RuntimeError("tshark not found. Install it: sudo apt-get install -y tshark")
    cmd = ["tshark", "-r", fn, "-T", "fields", "-E", "separator=,", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    if disp and str(disp).strip():
        cmd += ["-Y", disp]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()}")
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return [ln.split(",") for ln in lines]


# ---------- iperf3 RX-only loss ----------
def _iperf_rx_rows(fn: str, bpf: str, port: Optional[int]) -> List[Tuple[float, bytes, Optional[int], Optional[int]]]:
    """
    Return [(ts, payload_bytes, sport, dport), ...], filtered by bpf and port.
    Enforce data.len>=12 for iperf3 UDP header presence.
    """
    fields = ["frame.time_epoch", "data.data", "udp.srcport", "udp.dstport", "data.len"]
    disp = f"({bpf}) && data.len>=12" if bpf and str(bpf).strip() else "data.len>=12"
    rows = _rows_fields(fn, disp, fields)
    out: List[Tuple[float, bytes, Optional[int], Optional[int]]] = []
    for r in rows:
        ts = float(r[0]) if r[0] else None
        payload = _hex_to_bytes(r[1] if len(r) > 1 else "")
        sport = int(r[2]) if len(r) > 2 and r[2] else None
        dport = int(r[3]) if len(r) > 3 and r[3] else None
        dlen = int(r[4]) if len(r) > 4 and r[4] else 0
        if ts is None or dlen < 12 or len(payload) < 12:
            continue
        if port and port > 0:
            if sport != port and dport != port:
                continue
        out.append((ts, payload, sport, dport))
    return out

def _score_seq(arr: np.ndarray) -> float:
    """
    How sequential is this array? Percentage of diffs equal to 1.
    """
    if arr.size < 10:
        return 0.0
    d = np.diff(arr.astype(np.int64))
    return float(np.mean(d == 1))

def _detect_seq_params(rows: List[Tuple[float, bytes, Optional[int], Optional[int]]]) -> Tuple[int, str, float]:
    """
    Try multiple offsets/endians and pick the best by sequence score.
    Prefer iperf3 spec (offset=8, big-endian).
    """
    cand_offsets = [8, 0, 2, 4, 12]
    cand_endian = ["be", "le"]
    best = (8, "be", -1.0)

    sample = rows[:min(500, len(rows))]
    for off in cand_offsets:
        for ed in cand_endian:
            seqs = []
            for _, payload, _, _ in sample:
                if len(payload) >= off + 4:
                    seqs.append(int.from_bytes(payload[off:off+4], "big" if ed == "be" else "little", signed=False))
            if len(seqs) < 10:
                continue
            score = _score_seq(np.array(seqs))
            if score > best[2]:
                best = (off, ed, score)
    return best

def iperf_rx_seqs(
    fn: str,
    bpf: str,
    port: Optional[int],
    force_offset: int = -1,
    force_endian: str = "auto",
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, Tuple[int, str, float]]:
    """
    Parse iperf3 UDP sequence from RX pcap.
    Return (ts_array, seq_array, size_bytes_array, (offset, endian, score)).
    size_bytes_array 為 UDP payload長度（tshark data.data 長度）。
    """
    rows = _iperf_rx_rows(fn, bpf, port)
    if not rows:
        return np.array([]), np.array([]), np.array([]), (8, "be", 0.0)

    # Prefer iperf3 spec (offset=8, big-endian); allow override; fallback to detection
    if force_offset >= 0 or force_endian in ("be", "le"):
        off = max(0, force_offset) if force_offset >= 0 else 8
        ed = force_endian if force_endian in ("be", "le") else "be"
        score = -1.0
    else:
        # quick try: spec
        sample = rows[:min(200, len(rows))]
        seqs_try = []
        for _, payload, _, _ in sample:
            if len(payload) >= 12:
                seqs_try.append(int.from_bytes(payload[8:12], "big", signed=False))
        score_try = _score_seq(np.array(seqs_try)) if len(seqs_try) >= 10 else 0.0
        if score_try >= 0.5:
            off, ed, score = 8, "be", score_try
        else:
            off, ed, score = _detect_seq_params(rows)

    ts_list: List[float] = []
    seq_list: List[int] = []
    size_list: List[int] = []
    for ts, payload, _, _ in rows:
        if len(payload) >= off + 4:
            seq = int.from_bytes(payload[off:off+4], "big" if ed == "be" else "little", signed=False)
            ts_list.append(ts)
            seq_list.append(seq)
            size_list.append(len(payload))

    if not ts_list:
        return np.array([]), np.array([]), np.array([]), (off, ed, -1.0)

    idx = np.argsort(ts_list)
    ts_arr = np.array(ts_list, dtype=float)[idx]
    seq_arr = np.array(seq_list, dtype=np.int64)[idx]
    size_arr = np.array(size_list, dtype=np.int64)[idx]
    return ts_arr, seq_arr, size_arr, (off, ed, score)

def rxloss_from_seqs(seq_arr: np.ndarray, assume_start1: bool = False) -> Tuple[int, int, int, float, Optional[float]]:
    """
    Compute RX-only loss from iperf3 sequences.
    Returns (observed, uniq_observed, missing_between, interior_loss_rate, total_est_loss_rate?)
    """
    if seq_arr.size == 0:
        return 0, 0, 0, 0.0, None
    seq_sorted = np.array(sorted(set(seq_arr)))
    uniq = seq_sorted.size
    min_seq = int(seq_sorted[0])
    max_seq = int(seq_sorted[-1])
    expected_between = max_seq - min_seq + 1
    missing_between = expected_between - uniq
    interior_loss = (missing_between / expected_between) if expected_between > 0 else 0.0

    total_est = None
    if assume_start1:
        expected_total = max_seq  # 1..max_seq
        missing_total = max_seq - uniq
        total_est = (missing_total / expected_total) if expected_total > 0 else 0.0

    return seq_arr.size, uniq, missing_between, interior_loss, total_est

def write_rxloss_csv(out_csv: str, ts_arr: np.ndarray, seq_arr: np.ndarray):
    with open(out_csv, "w", newline="") as f:
        f.write("ts_epoch,seq\n")
        for t, s in zip(ts_arr, seq_arr):
            f.write(f"{t:.6f},{int(s)}\n")

# 估算封包速率（pps），用中位數斜率，較抗雜訊
def _estimate_rate_pps(ts: np.ndarray, seq: np.ndarray) -> float:
    if ts.size < 2:
        return 0.0
    dts = np.diff(ts)
    dss = np.diff(seq.astype(np.float64))
    m = (dts > 1e-6) & np.isfinite(dss)
    if not np.any(m):
        return 0.0
    pps = dss[m] / dts[m]
    # 去除極端值
    p95 = np.percentile(pps, 95) if pps.size >= 5 else np.max(pps)
    pps = pps[pps > 0]
    pps = pps[pps <= max(1.0, p95)]
    if pps.size == 0:
        # 後備：整體斜率
        total = (seq[-1] - seq[0]) / max(1e-6, ts[-1] - ts[0])
        return float(max(0.0, total))
    return float(np.median(pps))


# ---------- plotting helpers ----------
def _plot_seq_vs_time(label: str, ts: np.ndarray, seq: np.ndarray, out_png: str):
    if ts.size == 0:
        return
    t0 = ts[0]
    plt.figure(figsize=(9, 4))
    plt.plot(ts - t0, seq, ".", ms=1.0, alpha=0.8)
    plt.xlabel("Time since start (s)")
    plt.ylabel("iPerf3 sequence")
    plt.title(f"{label} - Seq vs Time")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()

def _window_loss(ts: np.ndarray, seq: np.ndarray, win_sec: float = 1.0, step_sec: Optional[float] = None,
                 mode: str = "rate", fill_empty_100: bool = True, reorder_grace_sec: float = 0.2):
    """
    mode:
      - 'span': 以該窗內的 seq_range 作為 expected（原本的作法）。
      - 'rate': 以估計的 pps 計 expected。
    reorder_grace_sec:
      - 對每個視窗 [lo, hi]，在計算收到的封包數時改用 [lo-grace, hi+grace] 以容忍重排序。
    """
    if ts.size == 0:
        return np.array([]), np.array([])
    if step_sec is None or step_sec <= 0:
        step_sec = max(win_sec / 4.0, 0.05)

    t_min, t_max = ts.min(), ts.max()
    centers = np.arange(t_min + win_sec/2, t_max - win_sec/2 + 1e-9, step_sec)
    times, losses = [], []

    est_pps = _estimate_rate_pps(ts, seq) if mode == "rate" else 0.0

    for c in centers:
        lo, hi = c - win_sec/2, c + win_sec/2
        # 以 grace 擴大視窗，降低跨窗重排序造成的假 loss
        lo_g, hi_g = lo - reorder_grace_sec, hi + reorder_grace_sec
        m = (ts >= lo_g) & (ts < hi_g)

        if not np.any(m):
            if mode == "rate" and est_pps > 0:
                times.append(c); losses.append(1.0 if fill_empty_100 else 0.0)
            elif fill_empty_100:
                times.append(c); losses.append(1.0)
            continue

        s = np.sort(np.unique(seq[m]))
        got = int(s.size)

        if mode == "span":
            exp = int(s[-1] - s[0] + 1) if s.size > 0 else 0
        else:  # rate
            exp = float(est_pps * (hi - lo))

        loss = 0.0 if exp <= 0 else max(0.0, min(1.0, 1.0 - (got / exp)))
        times.append(c)
        losses.append(loss)

    return np.array(times), np.array(losses)

def _plot_loss_timeline(label: str, ts: np.ndarray, seq: np.ndarray, win_sec: float, out_png: str,
                        step_sec: Optional[float] = None, ymax: Optional[float] = None,
                        mode: str = "rate", fill_empty_100: bool = True, reorder_grace_sec: float = 0.2):
    tt, ll = _window_loss(ts, seq, win_sec=win_sec, step_sec=step_sec, mode=mode,
                          fill_empty_100=fill_empty_100, reorder_grace_sec=reorder_grace_sec)
    t0 = ts[0] if ts.size else 0.0
    plt.figure(figsize=(9, 3))
    if tt.size > 0:
        y = ll * 100.0
        x = tt - t0
        plt.plot(x, y, "-", lw=1.6, color="#1f77b4")
        plt.scatter(x, y, s=8, color="#1f77b4", alpha=0.9)
        if ymax is not None and ymax > 0:
            plt.ylim(0, ymax)
        else:
            y_top = float(np.max(y)) if y.size else 0.0
            plt.ylim(0, max(1.0, y_top * 1.2))
    else:
        plt.text(0.5, 0.5, "No windows", ha="center", va="center", transform=plt.gca().transAxes)
        plt.ylim(0, 1.0)
    plt.xlabel("Time since start (s)")
    plt.ylabel(f"Loss in window ({win_sec:.2f}s) %")
    plt.title(f"{label} - Loss timeline ({mode}, grace={reorder_grace_sec:.2f}s)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()

# ---------- throughput helpers ----------
def _window_throughput(ts: np.ndarray, sizes_bytes: np.ndarray, win_sec: float = 1.0, step_sec: Optional[float] = None,
                       unit: str = "mbps") -> Tuple[np.ndarray, np.ndarray]:
    """
    視窗化吞吐：
      - unit='mbps'/'kbps': sum(bytes)*8 / win_sec 轉單位
      - unit='pps': count / win_sec
    回傳 (window_center_times, values)
    """
    if ts.size == 0 or sizes_bytes.size != ts.size:
        return np.array([]), np.array([])
    if step_sec is None or step_sec <= 0:
        step_sec = max(win_sec / 4.0, 0.05)

    t_min, t_max = ts.min(), ts.max()
    centers = np.arange(t_min + win_sec/2, t_max - win_sec/2 + 1e-9, step_sec)
    times, vals = [], []
    for c in centers:
        lo, hi = c - win_sec/2, c + win_sec/2
        m = (ts >= lo) & (ts < hi)
        if not np.any(m):
            times.append(c)
            vals.append(0.0)
            continue
        if unit == "pps":
            v = float(np.count_nonzero(m)) / win_sec
        else:
            bits = float(np.sum(sizes_bytes[m])) * 8.0
            bps = bits / win_sec
            if unit == "kbps":
                v = bps / 1e3
            else:
                v = bps / 1e6
        times.append(c)
        vals.append(v)
    return np.array(times), np.array(vals)

def _window_bins(ts: np.ndarray, sizes_bytes: np.ndarray, win_sec: float, step_sec: Optional[float]):
    if ts.size == 0 or sizes_bytes.size != ts.size:
        return np.array([]), np.array([]), np.array([])
    if step_sec is None or step_sec <= 0:
        step_sec = max(win_sec / 4.0, 0.05)
    t_min, t_max = ts.min(), ts.max()
    centers = np.arange(t_min + win_sec/2, t_max - win_sec/2 + 1e-9, step_sec)
    times, bytes_sum, counts = [], [], []
    for c in centers:
        lo, hi = c - win_sec/2, c + win_sec/2
        m = (ts >= lo) & (ts < hi)
        times.append(c)
        if np.any(m):
            bytes_sum.append(float(np.sum(sizes_bytes[m])))
            counts.append(int(np.count_nonzero(m)))
        else:
            bytes_sum.append(0.0)
            counts.append(0)
    return np.array(times), np.array(bytes_sum), np.array(counts)

def _auto_unit_from_bps(max_bps: float) -> str:
    if max_bps < 2_000.0:     # < 2 kbps → 用 pps 比較可讀
        return "pps"
    if max_bps < 2_000_000.0: # < 2 Mbps → kbps
        return "kbps"
    return "mbps"

def _plot_throughput_timeline(label: str, ts: np.ndarray, sizes_bytes: np.ndarray, win_sec: float, out_png: str,
                              step_sec: Optional[float] = None, ymax: Optional[float] = None,
                              unit: str = "auto", q_auto: float = 0.95, use_bar: bool = False):
    # 忽略 bar，用折線圖
    use_bar = False

    tt, bytes_sum, counts = _window_bins(ts, sizes_bytes, win_sec, step_sec)
    t0 = ts[0] if ts.size else 0.0
    bps = (bytes_sum * 8.0) / win_sec if tt.size else np.array([])
    pps = (counts.astype(float)) / win_sec if tt.size else np.array([])

    # --- 自動判斷單位 ---
    if unit == "auto":
        max_bps = float(np.max(bps)) if bps.size else 0.0
        unit = _auto_unit_from_bps(max_bps)

    if unit == "pps":
        vv = pps
        y_label = "Packets/s"
    elif unit == "kbps":
        vv = bps / 1e3
        y_label = "Throughput (Kbps)"
    else:
        vv = bps / 1e6
        y_label = "Throughput (Mbps)"

    # --- 從 prefix 擷取頻寬標籤，例如 10M、5Mbps ---
    import re
    m = re.search(r"(\d+\.?\d*)\s*(M|Mbps)", out_png, re.IGNORECASE)
    rate_label = f"{m.group(1)}M" if m else ""

    # --- 從 label 判斷是否冗餘 ---
    l_lower = label.lower()
    if any(x in l_lower for x in ["nored", "no_red", "no-red", "without", "wored"]):
        redundancy = "Without redundant"
    elif any(x in l_lower.split("_") + l_lower.split("-") + [l_lower] for x in ["red", "withred", "with_red"]):
        redundancy = "With redundant"
    else:
        redundancy = label  # fallback

    # --- 繪圖 ---
    plt.figure(figsize=(9, 3))
    if tt.size > 0:
        x = tt - t0
        plt.plot(x, vv, "-", lw=1.8, color="#2ca02c")
        plt.scatter(x, vv, s=10, color="#2ca02c", alpha=0.9)

        if ymax and ymax > 0:
            plt.ylim(0, ymax)
        else:
            nz = vv[vv > 0]
            if q_auto > 0 and nz.size > 0:
                y_top = float(np.quantile(nz, min(max(q_auto, 0.0), 1.0))) * 1.2
                y_top = max(y_top, float(np.max(nz)) * 1.05)
            else:
                y_top = float(np.max(vv)) * 1.2 if vv.size else 1.0
            plt.ylim(0, max(0.01, y_top))
    else:
        plt.text(0.5, 0.5, "No data", ha="center", va="center", transform=plt.gca().transAxes)
        plt.ylim(0, 1.0)

    plt.xlabel("Time (second)")
    plt.ylabel(y_label)
    if "detnet" in l_lower:
        system = "DetNet"
    elif "5g" in l_lower or "nr" in l_lower:
        system = "5G"
    else:
        system = ""

    # --- 標題組合 ---
    if system:
        plt.title(f"{system} – {redundancy} – Throughput: {rate_label}")
    else:
        plt.title(f"{redundancy} – Throughput: {rate_label}")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()

def _plot_loss_bar_comparison(prefix: str, loss_data: dict, outdir: str):
    """
    loss_data: dict like {'5G_10M': {'With': 0.0, 'Without': 0.3801}, 'DetNet_10M': {...}}
    """
    for key, vals in loss_data.items():
        system_label = key  # e.g. "5G_10M" or "DetNet_10M"
        loss_with = vals.get("With", 0.0) * 100.0
        loss_without = vals.get("Without", 0.0) * 100.0

        fig, ax = plt.subplots(figsize=(5, 5))
        streams = ["With Redundant", "Without Redundant"]
        losses = [loss_with, loss_without]
        bars = ax.bar(streams, losses, color=["#4daf4a", "#377eb8"])

        # 在柱子上顯示數值
        for bar, val in zip(bars, losses):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f"{val:.2f}%", ha="center", va="bottom", fontsize=10)

        ax.set_ylabel("Packet Loss Rate (%)")
        ax.set_xlabel("Stream Type")
        ax.set_ylim(0, max(50, max(losses) * 1.2))
        ax.set_title(f"{system_label} - Packet Loss Rate")
        plt.tight_layout()

        out_png = os.path.join(outdir, f"{prefix}_{system_label}_loss_comparison.png")
        plt.savefig(out_png, dpi=150)
        plt.close()
        print(f"[OK ] plotted {out_png}")

# ---------- CLI ----------
def parse_label_file(arg: str) -> Tuple[str, str]:
    s = str(arg).strip().strip('"').strip("'")
    if ":" not in s:
        raise ValueError(f"Input must be 'Label:filename', got: {arg}")
    label, fn = s.split(":", 1)
    return label.strip(), fn.strip()

def main():
    ap = argparse.ArgumentParser(description="RX-only iperf3 UDP loss estimator (NAT-safe) from PCAP via tshark.")
    ap.add_argument("prefix", help="Output prefix/run name used in filenames")
    ap.add_argument("--rxloss-iperf", nargs="*", help='One or more "Label:rx.pcap" for RX-only iperf3 UDP loss')
    ap.add_argument("--bpf", default="udp", help="Wireshark display filter, e.g. 'udp.port==5201'")
    ap.add_argument("--iperf-port", type=int, default=5201, help="UDP port used by iperf3 (additional filter)")
    ap.add_argument("--iperf-offset", type=int, default=-1, help="Force UDP payload offset of iperf3 seq; -1=auto (iperf3 spec prefers 8)")
    ap.add_argument("--iperf-endian", choices=["auto", "be", "le"], default="auto", help="Force endian of iperf3 seq; default auto")
    ap.add_argument("--iperf-assume-start1", action="store_true", help="Assume seq starts at 1 to estimate head loss")
    ap.add_argument("--rxloss-csv", action="store_true", help="Export CSV of observed iperf3 sequence")
    ap.add_argument("--outdir", default=".", help="Output directory")
    ap.add_argument("--debug", action="store_true", help="Print simple debug previews")
    # 繪圖選項
    ap.add_argument("--plot-iperf", action="store_true", help="Also plot seq-vs-time and loss timeline")
    ap.add_argument("--plot-window-sec", type=float, default=1.0, help="Window seconds for timelines")
    ap.add_argument("--plot-step-sec", type=float, default=0.0, help="Step seconds for sliding window (default win/4)")
    ap.add_argument("--plot-ymax", type=float, default=0.0, help="Fix Y max (percent) for loss timeline (0=auto)")
    ap.add_argument("--loss-mode", choices=["span", "rate"], default="rate", help="Windowed loss mode")
    ap.add_argument("--fill-empty-100", action="store_true", help="Treat empty windows as 100% loss")
    ap.add_argument("--loss-reorder-grace", type=float, default=0.2, help="Reordering grace seconds when computing windowed loss")
    # 吞吐選項
    ap.add_argument("--plot-throughput", action="store_true", help="Also plot throughput timeline")
    ap.add_argument("--throughput-unit", choices=["auto", "mbps", "kbps", "pps"], default="auto", help="Throughput unit")
    ap.add_argument("--throughput-ymax", type=float, default=0.0, help="Fix Y max for throughput plot (0=auto)")
    ap.add_argument("--throughput-ymax-quantile", type=float, default=0.95, help="Auto Y max from this quantile of non-zero data (0..1, 0=disabled)")
    ap.add_argument("--throughput-bar", action="store_true", help="[deprecated] Ignored; throughput is always a line plot")
    args = ap.parse_args()

    _ensure_outdir(args.outdir)

    if not args.rxloss_iperf:
        print("No --rxloss-iperf inputs. Nothing to do.")
        return

    for ent in args.rxloss_iperf:
        try:
            label, rx_pcap = parse_label_file(ent)
        except Exception as e:
            print(f"[ERR] bad --rxloss-iperf entry: {ent} ({e})")
            continue
        if not os.path.exists(rx_pcap):
            print(f"[ERR] file not found: {rx_pcap}")
            continue

        # Parse sequences
        ts_arr, seq_arr, size_arr, det = iperf_rx_seqs(
            rx_pcap, args.bpf, args.iperf_port,
            force_offset=args.iperf_offset, force_endian=args.iperf_endian
        )
        off, ed, score = det

        if ts_arr.size == 0 or seq_arr.size == 0:
            print(f"[RXLOSS] {label}: no iperf3 UDP payload/sequence found (check -s 0, --bpf, port).")
            continue

        if args.debug:
            head = ", ".join(str(int(x)) for x in seq_arr[:10])
            print(f"[DBG] {label}: off={off} endian={ed} score={score:.3f} head={head}")

        obs, uniq, missing_between, interior_loss, total_est = rxloss_from_seqs(
            seq_arr, assume_start1=args.iperf_assume_start1
        )

        print(f"[INFO] {label}: iperf-seq parse offset={off} endian={ed} score={score:.3f} (iperf3 spec: offset=8, endian=be)")
        msg = (f"[RXLOSS] {label}: packets(obs={obs}, uniq={uniq}), "
               f"seq_range=[{int(np.min(seq_arr))}..{int(np.max(seq_arr))}], "
               f"missing_between={missing_between}, interior_loss={interior_loss*100:.3f}%")
        if total_est is not None:
            msg += f", total_est(start@1)={total_est*100:.3f}%"
        print(msg)

        if args.rxloss_csv:
            out_csv = os.path.join(args.outdir, f"{args.prefix}_{label}_rxloss_iperf_seq.csv")
            write_rxloss_csv(out_csv, ts_arr, seq_arr)
            print(f"[OK ] wrote {out_csv}")

        # if args.plot_iperf:
        #     out_seq = os.path.join(args.outdir, f"{args.prefix}_{label}_seq_vs_time.png")
        #     out_loss = os.path.join(args.outdir, f"{args.prefix}_{label}_loss_timeline_{args.plot_window_sec:.2f}s.png")
        #     _plot_seq_vs_time(label, ts_arr, seq_arr, out_seq)
        #     _plot_loss_timeline(
        #         label, ts_arr, seq_arr, args.plot_window_sec, out_loss,
        #         step_sec=args.plot_step_sec if args.plot_step_sec > 0 else None,
        #         ymax=args.plot_ymax if args.plot_ymax > 0 else None,
        #         mode=args.loss_mode, fill_empty_100=args.fill_empty_100,
        #         reorder_grace_sec=args.loss_reorder_grace
        #     )
        #     print(f"[OK ] plotted {out_seq}")
        #     print(f"[OK ] plotted {out_loss}")

        if args.plot_throughput:
            out_thr = os.path.join(args.outdir, f"{args.prefix}_{label}_throughput_{args.plot_window_sec:.2f}s_{args.throughput_unit}.png")
            _plot_throughput_timeline(
                label, ts_arr, size_arr, args.plot_window_sec, out_thr,
                step_sec=args.plot_step_sec if args.plot_step_sec > 0 else None,
                ymax=args.throughput_ymax if args.throughput_ymax > 0 else None,
                unit=args.throughput_unit,
                q_auto=args.throughput_ymax_quantile,
                use_bar=args.throughput_bar
            )            
           
            print(f"[OK ] plotted {out_thr}")
        loss_summary = {}

    for ent in args.rxloss_iperf:
        label, rx_pcap = parse_label_file(ent)
        l_lower = label.lower()

        # Detect system
        if "detnet" in l_lower:
            system = "DetNet"
        elif "5g" in l_lower or "nr" in l_lower:
            system = "5G"
        else:
            system = "Unknown"

        # Detect rate (e.g., "10M", "5M")
        import re
        m = re.search(r"(\d+\.?\d*)m", args.prefix, re.IGNORECASE)
        rate = f"{m.group(1)}M" if m else ""

        key = f"{system}_{rate}"

        # Get corresponding loss
        ts_arr, seq_arr, size_arr, _ = iperf_rx_seqs(
            rx_pcap, args.bpf, args.iperf_port,
            force_offset=args.iperf_offset, force_endian=args.iperf_endian
        )
        _, _, _, interior_loss, _ = rxloss_from_seqs(seq_arr)
        if any(x in l_lower for x in ["nored", "no_red", "no-red", "without", "wored"]):
            mode = "Without"
        else:
            mode = "With"

        if key not in loss_summary:
            loss_summary[key] = {}
        loss_summary[key][mode] = interior_loss

    if loss_summary:
        _plot_loss_bar_comparison(args.prefix, loss_summary, args.outdir)



if __name__ == "__main__":
    main()