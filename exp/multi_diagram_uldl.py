#!/usr/bin/env python3
import json
import numpy as np
import matplotlib.pyplot as plt
import sys

def parse_iperf3_json(filename):
    with open(filename) as f:
        data = json.load(f)
    rates = [interval["sum"]["bits_per_second"]/1e6 for interval in data["intervals"]]
    return np.array(rates)

def plot_timeseries(datalist, labels, outfile):
    plt.figure()
    for rates, label in zip(datalist, labels):
        plt.plot(rates, marker='o', label=label)
    plt.xlabel("Interval (s)")
    plt.ylabel("Throughput (Mbps)")
    plt.title("Throughput Time Series")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outfile)
    plt.close()

def plot_cdf(datalist, labels, outfile):
    plt.figure()
    for rates, label in zip(datalist, labels):
        data = np.sort(rates)
        cdf = np.arange(1, len(data)+1) / len(data)
        plt.plot(data, cdf, label=label)
    plt.xlabel("Throughput (Mbps)")
    plt.ylabel("CDF")
    plt.title("Throughput CDF")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outfile)
    plt.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"用法: {sys.argv[0]} prefix 標籤1:file1.json 標籤2:file2.json ...")
        sys.exit(1)

    prefix = sys.argv[1]
    labels = []
    file_list = []
    for arg in sys.argv[2:]:
        if ':' in arg:
            label, fname = arg.split(':', 1)
            labels.append(label)
            file_list.append(fname)
        else:
            print(f"參數需為 標籤:檔名 格式，例如 測試A:a.json")
            sys.exit(1)

    datalist = [parse_iperf3_json(f) for f in file_list]

    plot_timeseries(datalist, labels, f"{prefix}_throughput_timeseries.png")
    plot_cdf(datalist, labels, f"{prefix}_throughput_cdf.png")
    print(f"已繪製 {prefix}_throughput_timeseries.png 和 {prefix}_throughput_cdf.png")