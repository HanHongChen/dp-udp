script="20251019_diagram2.py"
bandwidths=("1M" "3M" "5M" "10M") # 
with_red_date="20251117"
without_red_date="20251110"
out_dir="./20251117/exp2/"

for bw in "${bandwidths[@]}"; do

    # === 5G ===
    python3 ./$script ${bw}-5g \
        --rxloss-iperf 5G_WithoutRed:./$without_red_date/exp2/exp2-5g-ue-80s-${bw}-server.pcap \
                        5G_WithRed:./$with_red_date/exp2/exp2-5g-red-80s-${bw}-server.pcap \
        --bpf "udp.port==5201 && data.len>=12" --iperf-port 5201 \
        --iperf-offset 8 --iperf-endian be --plot-throughput \
        --plot-window-sec 1.0 --plot-step-sec 0.2 --throughput-unit auto \
        --throughput-ymax-quantile 0.8 --outdir "$out_dir"

    # === DetNet ===
    python3 ./$script ${bw}-detnet \
        --rxloss-iperf DetNet_WithoutRed:./$without_red_date/exp2/exp2-det-ue-80s-${bw}-server.pcap \
                        DetNet_WithRed:./$with_red_date/exp2/exp2-det-red-80s-${bw}-server.pcap \
        --bpf "udp.port==5201 && data.len>=12" --iperf-port 5201 \
        --iperf-offset 8 --iperf-endian be --plot-throughput \
        --plot-window-sec 1.0 --plot-step-sec 0.2 --throughput-unit auto \
        --throughput-ymax-quantile 0.8 --outdir "$out_dir"
done