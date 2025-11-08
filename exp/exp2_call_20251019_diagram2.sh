rate=10M
script="20251019_diagram2.py"
bandwidths=("1M" "3M" "5M" "10M")
with_red_date="20251102"
without_red_date="20251102"
out_dir="./20251102/exp2/"

for bw in "${bandwidths[@]}"; do

    # Without Redund
    python3 ./$script ${rate}-5g \
        --rxloss-iperf Without_Redundant:./$without_red_date/exp2/exp2-5g-ue-80s-${rate}-server.pcap With_Redundant:./$with_red_date/exp2/exp2-5g-red-80s-${rate}-server.pcap \
        --bpf "udp.port==5201 && data.len>=12" --iperf-port 5201 \
        --iperf-offset 8 --iperf-endian be --plot-iperf --plot-throughput \
        --plot-window-sec 1.0 --plot-step-sec 0.2 --throughput-unit auto \
        --throughput-ymax-quantile 0.8 --throughput-bar \
        --outdir "$out_dir"

    python3 ./$script ${rate}-detnet \
        --rxloss-iperf Without_Redundant:./$without_red_date/exp2/exp2-det-ue-80s-${rate}-server.pcap With_Redundant:./$with_red_date/exp2/exp2-det-red-80s-${rate}-server.pcap \
        --bpf "udp.port==5201 && data.len>=12" --iperf-port 5201 \
        --iperf-offset 8 --iperf-endian be --plot-iperf --plot-throughput \
        --plot-window-sec 1.0 --plot-step-sec 0.2 --throughput-unit auto \
        --throughput-ymax-quantile 0.8 --throughput-bar \
        --outdir "$out_dir"
done