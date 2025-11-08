#!/bin/bash

# 定義 bandwidth 陣列
script="20251103_diagram.py"
bandwidths=("1M")
with_red_date="20251105"
without_red_date="20251105"
out_dir="./20251105/exp1/"
for bw in "${bandwidths[@]}"; do
    python3 "$script" "$bw" \
        "Without_Redundant:./$without_red_date/exp1/exp1-ue1-ul-80s-${bw}-server.pcap" \
        "With_Redundant:./$with_red_date/exp1/exp1-red-ul-80s-${bw}-server.pcap" \
        --bpf "udp.port==5201" \
        --bin 1 --smooth 3 --annotate-means \
        --rate-threshold-mbps 0.1 \
        --jitter-xmax-ms 2.0 \
        --outdir "$out_dir"

    python3 "$script" "latency_${bw}" \
        --latpairs \
        "With_Redundant,tx:./$with_red_date/exp1/exp1-red-ul-80s-${bw}-client.pcap,rx:./$with_red_date/exp1/exp1-red-ul-80s-${bw}-server.pcap" \
        "Without_Redundant,tx:./$without_red_date/exp1/exp1-ue1-ul-80s-${bw}-client.pcap,rx:./$without_red_date/exp1/exp1-ue1-ul-80s-${bw}-server.pcap" \
        --lat-mode iperf --lat-port 5201 \
        --outdir "$out_dir"

done
