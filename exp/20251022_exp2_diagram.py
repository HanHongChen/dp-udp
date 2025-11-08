#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 這是從 20251019_diagram2.py 修改而來的腳本
# 增加功能：
# 1. 產出時間、序列號、吞吐量的CSV檔案
# 2. 新增多個流量的封包遺失率比較圖表（長條圖）

import argparse
import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import EngFormatter


def _parse_loss_specs(spec_list: List[str]) -> Dict[str, str]:
    specs = {}
    for s in spec_list:
        parts = s.split(":", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            warnings.warn(f"Invalid loss spec (need LABEL:PCAP_PATH): {s}")
            continue
        label, pcap = parts
        specs[label] = pcap
    return specs


def _get_iperf_udp_pcap_sequences(pcap_path: str, iperf_port: Optional[int] = None,
                                   filter_extra: Optional[str] = None) -> List[Tuple[float, bytes, int]]:
    """
    從 PCAP 檔案中提取 iperf3 UDP 序列號（使用 tshark）
    返回 (時間戳, 資料內容, 長度) 列表
    """
    # 檢查 tshark 是否存在
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        warnings.warn("tshark not found in PATH, cannot extract sequences")
        return []

    filter_parts = []
    filter_parts.append("udp")
    if iperf_port is not None:
        filter_parts.append(f"(udp.srcport == {iperf_port} or udp.dstport == {iperf_port})")
    if filter_extra:
        filter_parts.append(f"({filter_extra})")

    display_filter = " and ".join(filter_parts)
    cmd = [
        tshark_bin,
        "-r", pcap_path,
        "-T", "fields",
        "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "data.data",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "data.len",
        "-Y", display_filter
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        warnings.warn(f"tshark failed: {result.stderr}")
        return []

    packets = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split(",")
        if len(parts) < 5 or not parts[1]:  # 需要時間戳和資料內容
            continue
        ts = float(parts[0])
        # 從十六進制轉為二進制
        hex_data = parts[1].replace(":", "")
        data = bytes.fromhex(hex_data)
        data_len = int(parts[4])
        packets.append((ts, data, data_len))

    return packets


def _extract_be_int(data: bytes, offset: int, size: int = 4) -> Optional[int]:
    """從二進制資料的指定偏移量提取大端整數"""
    if offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], byteorder="big")


def _extract_le_int(data: bytes, offset: int, size: int = 4) -> Optional[int]:
    """從二進制資料的指定偏移量提取小端整數"""
    if offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], byteorder="little")


def _detect_iperf_seq_offset(packets: List[Tuple[float, bytes, int]],
                             likely_offset: int = 8,
                             max_check: int = 20) -> Tuple[Optional[int], str]:
    """
    檢測 iperf3 UDP 序列號的偏移量和端序
    返回 (偏移量, 端序) 或 (None, "") 表示未檢測到
    """
    if not packets:
        return None, ""

    # 首先嘗試默認偏移量 8
    offset = likely_offset
    # 嘗試大端和小端
    candidates = [
        (offset, "be", _extract_be_int),
        (offset, "le", _extract_le_int)
    ]

    for off, endian, extract_func in candidates:
        count = min(max_check, len(packets))
        seqs = []
        for i in range(count):
            ts, data, dlen = packets[i]
            if len(data) <= off:
                continue
            seq = extract_func(data, off)
            if seq is not None and 0 <= seq <= 0xFFFFFFFE:  # 合理的序列號範圍
                seqs.append(seq)

        if seqs and len(seqs) >= count * 0.5:  # 至少 50% 的封包有序列號
            # 檢查序列號是否大致遞增
            is_increasing = all(seqs[i] <= seqs[i + 1] + 10 for i in range(len(seqs) - 1))
            if is_increasing:
                return off, endian

    # 如果默認偏移量失敗，嘗試其他可能的偏移量
    for off in range(0, 16):
        if off == likely_offset:
            continue  # 已嘗試過
        for endian, extract_func in [("be", _extract_be_int), ("le", _extract_le_int)]:
            count = min(max_check, len(packets))
            seqs = []
            for i in range(count):
                ts, data, dlen = packets[i]
                if len(data) <= off:
                    continue
                seq = extract_func(data, off)
                if seq is not None and 0 <= seq <= 0xFFFFFFFE:
                    seqs.append(seq)

            if seqs and len(seqs) >= count * 0.5:
                is_increasing = all(seqs[i] <= seqs[i + 1] + 10 for i in range(len(seqs) - 1))
                if is_increasing:
                    return off, endian

    return None, ""


def _extract_iperf_seq(packets: List[Tuple[float, bytes, int]],
                       offset: int, endian: str) -> List[Tuple[float, int]]:
    """
    使用指定偏移量和端序從封包中提取序列號
    返回 (時間戳, 序列號) 列表
    """
    seqs = []
    extract_func = _extract_be_int if endian == "be" else _extract_le_int
    for ts, data, dlen in packets:
        if len(data) <= offset:
            continue
        seq = extract_func(data, offset)
        if seq is not None and 0 <= seq <= 0xFFFFFFFE:
            seqs.append((ts, seq))
    return seqs


def _window_bins(ts: np.ndarray, values: np.ndarray, win_sec: float = 1.0, step_sec: Optional[float] = None
                 ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    將資料分組到時間窗格中計算總和和計數
    返回 (窗格中心時間, 值總和, 計數) 陣列
    """
    if ts.size == 0:
        return np.array([]), np.array([]), np.array([])
    if step_sec is None or step_sec <= 0:
        step_sec = max(win_sec / 4.0, 0.05)

    t_min, t_max = ts.min(), ts.max()
    centers = np.arange(t_min + win_sec/2, t_max - win_sec/2 + 1e-9, step_sec)
    sums, counts = [], []

    for c in centers:
        lo, hi = c - win_sec/2, c + win_sec/2
        m = (ts >= lo) & (ts < hi)
        s = np.sum(values[m]) if np.any(m) else 0
        k = int(np.sum(m))
        sums.append(s)
        counts.append(k)

    return np.array(centers), np.array(sums), np.array(counts)


def _estimate_rate_pps(ts: np.ndarray, seq: np.ndarray) -> float:
    """估計每秒封包數 (packets per second)"""
    if ts.size < 2:
        return 0.0
    duration = ts[-1] - ts[0]
    if duration <= 0.0:
        return 0.0
    # 使用兩種方法：計數和序列號跨度
    rate1 = ts.size / duration  # 基於觀察到的封包數
    # 基於序列號跨度 (假設連續)
    seq_min, seq_max = int(np.min(seq)), int(np.max(seq))
    seq_span = seq_max - seq_min + 1
    rate2 = seq_span / duration
    # 取較大的估計值，因為可能有丟失的封包
    return max(rate1, rate2)


def _window_loss(ts: np.ndarray, seq: np.ndarray, win_sec: float = 1.0, step_sec: Optional[float] = None,
                 mode: str = "rate", fill_empty_100: bool = True, reorder_grace_sec: float = 0.2):
    """
    計算窗格內的封包丟失率
    mode:
      - 'span': 以該窗內的 seq_range 作為 expected（原本的作法）。
      - 'rate': 以估計的 pps 計算 expected。
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


def _auto_unit_from_bps(bps: float) -> str:
    """根據速率自動選擇單位"""
    if bps < 2e6:
        return "kbps"
    return "mbps"


def _plot_seq_vs_time(label: str, ts: np.ndarray, seq: np.ndarray, out_png: str):
    """繪製序列號隨時間的變化圖"""
    if ts.size == 0:
        warnings.warn(f"{label}: No data for seq vs time plot")
        plt.figure(figsize=(9, 3))
        plt.text(0.5, 0.5, "No data", ha="center", va="center", transform=plt.gca().transAxes)
        plt.tight_layout()
        plt.savefig(out_png, dpi=150)
        plt.close()
        return

    t0 = ts[0]
    x = ts - t0
    # 只畫每個時間點的一個值（可能有重複序列號）
    seen = set()
    x_clean, seq_clean = [], []
    for i in range(len(x)):
        k = (x[i], seq[i])
        if k not in seen:
            x_clean.append(x[i])
            seq_clean.append(seq[i])
            seen.add(k)

    plt.figure(figsize=(9, 3))
    plt.scatter(x_clean, seq_clean, s=2, marker=".", alpha=0.5)
    plt.xlabel("Time since start (s)")
    plt.ylabel("Sequence number")
    plt.title(f"{label} - Sequence vs Time")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()


def _plot_loss_timeline(label: str, ts: np.ndarray, seq: np.ndarray, win_sec: float, out_png: str,
                        step_sec: Optional[float] = None, ymax: Optional[float] = None,
                        mode: str = "rate", fill_empty_100: bool = True, reorder_grace_sec: float = 0.2):
    """繪製封包遺失率隨時間的變化圖"""
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


def _plot_throughput_timeline(label: str, ts: np.ndarray, sizes_bytes: np.ndarray, win_sec: float, out_png: str,
                              step_sec: Optional[float] = None, ymax: Optional[float] = None,
                              unit: str = "auto", q_auto: float = 0.95, use_bar: bool = False):
    """繪製吞吐量隨時間的變化圖（使用折線圖）"""
    # 一律用折線圖（忽略 bar/面積）
    use_bar = False
    tt, bytes_sum, counts = _window_bins(ts, sizes_bytes, win_sec, step_sec)
    t0 = ts[0] if ts.size else 0.0
    bps = (bytes_sum * 8.0) / win_sec if tt.size else np.array([])
    pps = (counts.astype(float)) / win_sec if tt.size else np.array([])
    if unit == "auto":
        max_bps = float(np.max(bps)) if bps.size else 0.0
        unit = _auto_unit_from_bps(max_bps)
    if unit == "pps":
        vv = pps; y_label = f"Packets/s (win={win_sec:.2f}s)"
    elif unit == "kbps":
        vv = bps / 1e3; y_label = f"Throughput (Kbit/s) (win={win_sec:.2f}s)"
    else:
        vv = bps / 1e6; y_label = f"Throughput (Mbit/s) (win={win_sec:.2f}s)"
    plt.figure(figsize=(9, 3))
    if tt.size > 0:
        x = tt - t0
        plt.plot(x, vv, "-", lw=1.8, color="#2ca02c")
        plt.scatter(x, vv, s=10, color="#2ca02c", alpha=0.9)
        if ymax is not None and ymax > 0:
            plt.ylim(0, ymax)
        else:
            nz = vv[vv > 0]
            if q_auto > 0 and nz.size > 0:
                y_top = float(np.quantile(nz, min(max(q_auto, 0.0), 1.0))) * 1.2
                y_top = max(y_top, float(np.max(nz)) * 1.05)
            else:
                y_top = float(np.max(vv)) * 1.2 if vv.size else 1.0
            plt.ylim(0, max(0.5 if unit == "pps" else 0.01, y_top))
    else:
        plt.text(0.5, 0.5, "No windows", ha="center", va="center", transform=plt.gca().transAxes)
        plt.ylim(0, 1.0)
    plt.xlabel("Time since start (s)")
    plt.ylabel(y_label)
    plt.title(f"{label} - Throughput timeline ({unit})")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()


def _plot_multi_loss_comparison(prefix: str, label_losses: Dict[str, float], out_png: str):
    """繪製多個流量的封包丟失率比較圖（長條圖）"""
    if not label_losses:
        warnings.warn("No data for multi-loss comparison plot")
        plt.figure(figsize=(9, 5))
        plt.text(0.5, 0.5, "No data", ha="center", va="center", transform=plt.gca().transAxes)
        plt.tight_layout()
        plt.savefig(out_png, dpi=150)
        plt.close()
        return

    plt.figure(figsize=(max(5, len(label_losses) * 1.2), 5))
    
    labels = list(label_losses.keys())
    loss_values = [label_losses[label] * 100.0 for label in labels]  # 轉為百分比
    
    # 繪製長條圖
    bars = plt.bar(labels, loss_values, color='#1f77b4')
    
    # 在每個長條上顯示數值
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                 f'{height:.2f}%',
                 ha='center', va='bottom', fontsize=10)
    
    plt.xlabel('Stream')
    plt.ylabel('Packet Loss Rate (%)')
    plt.title(f'{prefix} - Packet Loss Rate Comparison')
    plt.grid(True, axis='y', alpha=0.3)
    
    # 調整 y 軸範圍以留出空間給標籤
    y_max = max(loss_values) * 1.2 if loss_values else 1.0
    plt.ylim(0, max(1.0, y_max))
    
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()


def _save_ts_seq_csv(ts_seq_list: List[Tuple[float, int]], out_csv: str):
    """將時間戳和序列號保存到 CSV 檔案"""
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ts_epoch", "seq"])
        for ts, seq in ts_seq_list:
            writer.writerow([f"{ts:.6f}", seq])


def _save_throughput_csv(ts: np.ndarray, sizes_bytes: np.ndarray, win_sec: float, out_csv: str,
                         step_sec: Optional[float] = None):
    """將吞吐量資料保存到 CSV 檔案"""
    tt, bytes_sum, counts = _window_bins(ts, sizes_bytes, win_sec, step_sec)
    t0 = ts[0] if ts.size else 0.0
    
    # 計算 bps 和 kbps
    bps = (bytes_sum * 8.0) / win_sec if tt.size else np.array([])
    kbps = bps / 1e3
    
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["time_since_start", "ts_epoch", "kbps"])
        for i in range(len(tt)):
            writer.writerow([f"{tt[i]-t0:.6f}", f"{tt[i]:.6f}", f"{kbps[i]:.2f}"])


def main():
    ap = argparse.ArgumentParser(description="RX-only iperf3 UDP loss estimator (NAT-safe) from PCAP via tshark.")
    ap.add_argument("prefix", help="Output prefix for filenames (e.g., run1)")
    ap.add_argument("--outdir", default=".", help="Output directory (default: .)")
    
    # 吞吐和丟失率繪圖選項
    ap.add_argument("--plot-window-sec", type=float, default=1.0, help="Window size in seconds for loss/throughput plots (default: 1.0)")
    ap.add_argument("--plot-step-sec", type=float, default=0.0, help="Step size in seconds for plot windows; 0=auto (default: 0)")
    ap.add_argument("--plot-ymax", type=float, default=0.0, help="Fix Y max for loss plot (0=auto)")
    ap.add_argument("--loss-mode", choices=["span", "rate"], default="rate", help="Windowed loss mode")
    ap.add_argument("--fill-empty-100", action="store_true", help="Treat empty windows as 100% loss")
    ap.add_argument("--loss-reorder-grace", type=float, default=0.2, help="Reordering grace seconds when computing windowed loss")
    
    # 吞吐選項
    ap.add_argument("--plot-throughput", action="store_true", help="Also plot throughput timeline")
    ap.add_argument("--throughput-unit", choices=["auto", "mbps", "kbps", "pps"], default="auto", help="Throughput unit")
    ap.add_argument("--throughput-ymax", type=float, default=0.0, help="Fix Y max for throughput plot (0=auto)")
    ap.add_argument("--throughput-ymax-quantile", type=float, default=0.95, help="Auto Y max from this quantile of non-zero data (0..1, 0=disabled)")
    ap.add_argument("--throughput-bar", action="store_true", help="[deprecated] Ignored; throughput is always a line plot")
    
    # iperf RX 選項
    ap.add_argument("--rxloss-iperf", nargs='+', default=[], help="One or more 'LABEL:PCAP_FILE' specifications for iperf3 UDP RX loss calc (from sequence gaps)")
    ap.add_argument("--iperf-port", type=int, default=5201, help="iperf3 port to filter (default: 5201)")
    ap.add_argument("--iperf-filter", help="Extra tshark display filter for iperf UDP packets")
    ap.add_argument("--plot-iperf", action="store_true", help="Also plot sequence vs. time for iperf")
    
    # CSV 輸出選項
    ap.add_argument("--rxloss-csv", action="store_true", help="Save sequence and timestamp to CSV")
    ap.add_argument("--throughput-csv", action="store_true", help="Save throughput data to CSV")
    
    # 多流量丟失率比較圖
    ap.add_argument("--plot-loss-comparison", action="store_true", help="Generate packet loss rate comparison bar chart")
    
    args = ap.parse_args()
    
    # 確保輸出目錄存在
    os.makedirs(args.outdir, exist_ok=True)
    
    # 處理 iperf3 UDP 序列號的丟失計算
    iperf_specs = _parse_loss_specs(args.rxloss_iperf)
    if not iperf_specs:
        warnings.warn("No iperf loss specs provided")
    
    label_losses = {}  # 用於保存每個標籤的丟失率，用於多流量比較
    
    for label, pcap_path in iperf_specs.items():
        print(f"[INFO] 正在處理 {label}: {pcap_path}")
        # 提取封包
        packets = _get_iperf_udp_pcap_sequences(pcap_path, args.iperf_port, args.iperf_filter)
        if not packets:
            print(f"[RXLOSS] {label}: 找不到 iperf3 UDP 封包")
            continue
        
        # 檢測序列號偏移量
        offset, endian = _detect_iperf_seq_offset(packets)
        if offset is None:
            print(f"[RXLOSS] {label}: 未找到 iperf3 UDP 序列號")
            continue
        print(f"[INFO] {label}: iperf-seq parse offset={offset} endian={endian}")
        
        # 提取序列號
        ts_seq_list = _extract_iperf_seq(packets, offset, endian)
        if not ts_seq_list:
            print(f"[RXLOSS] {label}: 無法從封包提取序列號")
            continue
        
        # 轉換為 numpy 陣列以進行處理
        ts_arr = np.array([ts for ts, _ in ts_seq_list])
        seq_arr = np.array([seq for _, seq in ts_seq_list])
        size_arr = np.array([size for _, _, size in packets])
        
        # 基本統計資訊
        obs_cnt = len(ts_seq_list)
        uniq_cnt = len(set(seq for _, seq in ts_seq_list))
        seq_min = int(min(seq for _, seq in ts_seq_list))
        seq_max = int(max(seq for _, seq in ts_seq_list))
        expected_packets = seq_max - seq_min + 1
        missing = expected_packets - uniq_cnt
        if expected_packets > 0:
            loss_pct = missing / expected_packets * 100.0
        else:
            loss_pct = 0.0
        
        print(f"[RXLOSS] {label}: packets(obs={obs_cnt}, uniq={uniq_cnt}), seq_range=[{seq_min}..{seq_max}], missing_between={missing}, interior_loss={loss_pct:.3f}%")
        
        # 保存丟失率用於多流量比較
        label_losses[label] = missing / expected_packets if expected_packets > 0 else 0.0
        
        # 保存序列號資料到 CSV
        if args.rxloss_csv:
            out_csv = os.path.join(args.outdir, f"{args.prefix}_{label}_rxloss_iperf_seq.csv")
            _save_ts_seq_csv(ts_seq_list, out_csv)
            print(f"[OK ] 寫入序列號資料到 {out_csv}")
        
        # 保存吞吐量資料到 CSV
        if args.throughput_csv:
            out_thr_csv = os.path.join(args.outdir, f"{args.prefix}_{label}_throughput.csv")
            _save_throughput_csv(ts_arr, size_arr, args.plot_window_sec, out_thr_csv,
                               step_sec=args.plot_step_sec if args.plot_step_sec > 0 else None)
            print(f"[OK ] 寫入吞吐量資料到 {out_thr_csv}")
        
        # 繪製序列號隨時間變化圖
        if args.plot_iperf:
            out_seq = os.path.join(args.outdir, f"{args.prefix}-{label}_seq_vs_time.png")
            _plot_seq_vs_time(label, ts_arr, seq_arr, out_seq)
            print(f"[OK ] 繪製序列號圖 {out_seq}")
        
        # 繪製丟失率隨時間變化圖
        out_loss = os.path.join(args.outdir, f"{args.prefix}-{label}_loss_timeline_{args.plot_window_sec:.2f}s.png")
        _plot_loss_timeline(
            label, ts_arr, seq_arr, args.plot_window_sec, out_loss,
            step_sec=args.plot_step_sec if args.plot_step_sec > 0 else None,
            ymax=args.plot_ymax if args.plot_ymax > 0 else None,
            mode=args.loss_mode, fill_empty_100=args.fill_empty_100,
            reorder_grace_sec=args.loss_reorder_grace
        )
        print(f"[OK ] 繪製丟失率圖 {out_loss}")
        
        # 繪製吞吐量隨時間變化圖
        if args.plot_throughput:
            out_thr = os.path.join(args.outdir, f"{args.prefix}-{label}_throughput_{args.plot_window_sec:.2f}s_{args.throughput_unit}.png")
            _plot_throughput_timeline(
                label, ts_arr, size_arr, args.plot_window_sec, out_thr,
                step_sec=args.plot_step_sec if args.plot_step_sec > 0 else None,
                ymax=args.throughput_ymax if args.throughput_ymax > 0 else None,
                unit=args.throughput_unit,
                q_auto=args.throughput_ymax_quantile,
                use_bar=args.throughput_bar
            )
            print(f"[OK ] 繪製吞吐量圖 {out_thr}")
    
    # 繪製多流量丟失率比較圖
    if args.plot_loss_comparison and label_losses:
        out_comp = os.path.join(args.outdir, f"{args.prefix}_loss_comparison.png")
        _plot_multi_loss_comparison(args.prefix, label_losses, out_comp)
        print(f"[OK ] 繪製丟失率比較圖 {out_comp}")
    elif args.plot_loss_comparison:
        print("[WARN] 無法繪製丟失率比較圖：沒有可用資料")


if __name__ == "__main__":
    main()
