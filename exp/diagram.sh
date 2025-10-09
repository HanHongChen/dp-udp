#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt
import sys
import pyshark

def parse_udp_pcap(filename, port=None):
    cap = pyshark.FileCapture(filename, display_filter='udp')
    times = []
    sizes = []
    for pkt in cap:
        if hasattr(pkt, 'udp'):
            # 過濾 port（可選）
            if port and int(pkt.udp.dstport) != port and int(pkt.udp.srcport) != port:
                continue
            times.append(float(pkt.frame_info.time_epoch))
            sizes.append(int(pkt.length))
    cap.close()
    times = np.array(times)
    sizes = np.array(sizes)
    return times, sizes

def calc_throughput(times, sizes, interval=1.0):
    # 以 interval 秒為單位計算吞吐量（Mbps）
    if len(times) == 0:
        return np.array([])
    start = times[0]
    end = times[-1]
    bins = np.arange(start, end+interval, interval)
    byte_hist, _ = np.histogram(times, bins=bins, weights=sizes)
    mbps_hist = byte_hist * 8 / 1e6 / interval
    return mbps_hist

def calc_delay(times):
    # 到達間隔（秒）
    return np.diff(times)

def calc_jitter(delays):
    # 包間隔變化
    return np.abs(np.diff(delays))

def plot_timeseries(datalist, labels, ylabel, outfile):
    plt.figure()
    for data, label in zip(datalist, labels):
        plt.plot(data, marker='o', label=label)
    plt.xlabel("Interval (s)")
    plt.ylabel(ylabel)
    plt.title(f"{ylabel} Time Series")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outfile)
    plt.close()

def plot_cdf(datalist, labels, xlabel, outfile):
    plt.figure()
    for data, label in zip(datalist, labels):
        data = np.sort(data)
        cdf = np.arange(1, len(data)+1) / len(data)
        plt.plot(data, cdf, label=label)
    plt.xlabel(xlabel)
    plt.ylabel("CDF")
    plt.title(f"{xlabel} CDF")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outfile)
    plt.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"用法: {sys.argv[0]} prefix 標籤:pcap1 [標籤2:pcap2 ...] [port]")
        print("範例: ./pcap_udp_stats_plot.py test 測試A:a.pcap 測試B:b.pcap 5201")
        sys.exit(1)

    prefix = sys.argv[1]
    labels = []
    files = []
    port = None

    # 可選 port
    for arg in sys.argv[2:]:
        if arg.isdigit():
            port = int(arg)
        elif ':' in arg:
            label, fname = arg.split(':', 1)
            labels.append(label)
            files.append(fname)
        else:
            print(f"參數需為 標籤:檔名 格式，例如 測試A:a.pcap 或 UDP port，例如 5201")
            sys.exit(1)

    # 依序分析每個 pcap
    throughput_list = []
    delay_list = []
    jitter_list = []
    for fname in files:
        times, sizes = parse_udp_pcap(fname, port)
        tput = calc_throughput(times, sizes)
        delay = calc_delay(times)
        jitter = calc_jitter(delay)
        throughput_list.append(tput)
        delay_list.append(delay)
        jitter_list.append(jitter)

    # 畫 throughput
    plot_timeseries(throughput_list, labels, "Throughput (Mbps)", f"{prefix}_throughput_timeseries.png")
    plot_cdf(throughput_list, labels, "Throughput (Mbps)", f"{prefix}_throughput_cdf.png")
    # 畫 delay
    plot_timeseries(delay_list, labels, "Delay (s)", f"{prefix}_delay_timeseries.png")
    plot_cdf(delay_list, labels, "Delay (s)", f"{prefix}_delay_cdf.png")
    # 畫 jitter
    plot_timeseries(jitter_list, labels, "Jitter (s)", f"{prefix}_jitter_timeseries.png")
    plot_cdf(jitter_list, labels, "Jitter (s)", f"{prefix}_jitter_cdf.png")

    print(f"已繪製: {prefix}_throughput_timeseries.png, {prefix}_throughput_cdf.png, {prefix}_delay_timeseries.png, {prefix}_delay_cdf.png, {prefix}_jitter_timeseries.png, {prefix}_jitter_cdf.png")