#!/usr/bin/env python3
import argparse, os, shutil, subprocess
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def has_tshark():
    return shutil.which("tshark") is not None

def parse_label_file(arg: str):
    if ":" not in arg:
        raise ValueError(f"{arg} 需為 Label:path 格式")
    lab, fn = arg.split(":", 1)
    return lab.strip(), fn.strip()

def load_tcp_basic(pcap: str, port: int):
    if not has_tshark():
        raise SystemExit("tshark not found")
    disp = f"tcp.port=={port}"
    fields = ["frame.time_epoch","tcp.seq","tcp.len","tcp.analysis.retransmission"]
    cmd = ["tshark","-r",pcap,"-T","fields","-n"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-Y", disp, "-E","separator=,","-E","occurrence=f"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"tshark failed: {r.stderr.splitlines()[-1] if r.stderr else 'unknown'}")
    ts=[]; sizes=[]; is_retx=[]
    for ln in r.stdout.splitlines():
        if not ln.strip(): continue
        parts=ln.strip().split(",")
        if len(parts) < 4: continue
        try:
            t=float(parts[0])
            ln_bytes=int(parts[2])
            retx_flag = parts[3] != ""  # 有值表示重傳
            ts.append(t); sizes.append(ln_bytes); is_retx.append(retx_flag)
        except:
            continue
    return np.array(ts), np.array(sizes), np.array(is_retx, dtype=bool)

def throughput_series(ts: np.ndarray, sizes: np.ndarray, win: float):
    if ts.size==0: return np.array([]), np.array([])
    t0=ts.min(); t1=ts.max()
    bins=int(np.ceil((t1-t0)/win))
    edges=np.linspace(t0, t0+bins*win, bins+1)
    bytes_per_bin,_=np.histogram(ts, bins=edges, weights=sizes)
    mbps=(bytes_per_bin*8)/(win*1e6)
    x=np.arange(bins)*win
    return x, mbps

def smooth(arr: np.ndarray, k: int):
    if k<=1 or arr.size==0: return arr
    k=min(k, arr.size)
    kernel=np.ones(k)/k
    sm=np.convolve(arr, kernel, mode="valid")
    # 前面填充，使長度一致
    pad=np.full(arr.size - sm.size, sm[0])
    return np.concatenate([pad, sm])

def plot_multi(prefix, series, outdir, ytick_step: float, ymin: float, ymax: float):
    if not series: return
    # 從 prefix 推斷 System 與速率
    pfx = str(prefix).lower()
    if "detnet" in pfx or "det" in pfx:
        system = "DetNet"
    elif "5g" in pfx or "nr" in pfx:
        system = "5G"
    else:
        system = ""
    import re
    m = re.search(r"(\d+(?:\.\d+)?)\s*[mM]\b", prefix)
    rate_label = f"{m.group(1)}M" if m else ""

    plt.figure(figsize=(8, 6))
    ymax_data=0.0
    for lab,(x,y) in series.items():
        plt.plot(x,y,label=lab,linewidth=1.2)
        if y.size: ymax_data=max(ymax_data, y.max())

    plt.xlabel("Time (second)")
    plt.ylabel("Throughput (Mbps)")
    # 標題：{System} – TCP Throughput: {rate}
    if system and rate_label:
        title_txt = f"{system} – TCP Throughput: {rate_label}"
    elif system:
        title_txt = f"{system} – TCP Throughput"
    elif rate_label:
        title_txt = f"TCP Throughput: {rate_label}"
    else:
        title_txt = "TCP Throughput"
    plt.title(title_txt)

    plt.grid(True, alpha=0.35)
    plt.legend()

    # y 軸上下界
    lo = 0 if ymin is None else ymin
    hi = (ymax if (ymax is not None and ymax>0) else (ymax_data*1.15 if ymax_data>0 else 1.0))
    plt.ylim(lo, hi)

    # y 軸刻度
    if ytick_step and ytick_step>0:
        ticks=np.arange(lo, hi + 1e-9, ytick_step)
        plt.yticks(ticks)

    out=os.path.join(outdir, f"{prefix}_tcp_throughput_multi.png")
    plt.tight_layout()
    plt.savefig(out); plt.close()
    print(f"[OK] {out}")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("prefix")
    ap.add_argument("--inputs", nargs="+", required=True, help="Label:pcap ...")
    ap.add_argument("--port", type=int, default=5201)
    ap.add_argument("--win", type=float, default=1.0, help="bin/window 秒")
    ap.add_argument("--smooth", type=int, default=1, help="滑動平均窗口大小")
    ap.add_argument("--ytick-step", type=float, default=0.0, help="y 軸刻度間隔 (0=自動)")
    ap.add_argument("--ymin", type=float, default=0.0, help="y 軸下界 (預設 0)")
    ap.add_argument("--ymax", type=float, default=0.0, help="y 軸上界 (0=自動)")
    ap.add_argument("--outdir", default=".")
    args=ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    series={}
    for token in args.inputs:
        lab, fn = parse_label_file(token)
        if not os.path.isfile(fn):
            print(f"[WARN] 找不到檔案: {fn}")
            continue
        ts, sizes, retx = load_tcp_basic(fn, args.port)
        x, mbps = throughput_series(ts, sizes, args.win)
        if args.smooth>1:
            mbps = smooth(mbps, args.smooth)
        series[lab]=(x, mbps)
        total_pkts = ts.size
        retx_pkts = retx.sum()
        total_bytes = sizes.sum()
        retx_bytes = sizes[retx].sum()
        print(f"[STAT] {lab}: pkts={total_pkts}, retx={retx_pkts} ({retx_pkts*100/total_pkts if total_pkts else 0:.2f}%), bytes={total_bytes}, retx_bytes={retx_bytes} ({retx_bytes*100/total_bytes if total_bytes else 0:.2f}%)")

    plot_multi(args.prefix, series, args.outdir, args.ytick_step, args.ymin, args.ymax)

if __name__=="__main__":
    main()