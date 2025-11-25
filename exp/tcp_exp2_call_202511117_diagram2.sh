script="tcp_20251117_diagram2.py"
bandwidths=( "1M" "3M"   "5M" "10M" ) # 
with_red_date="20251122"
without_red_date="20251122"
out_dir="./20251122/exp2/"


bw_to_mbps() {
  local s="$1"
  awk -v s="$s" '
    BEGIN{
      if (match(s, /^([0-9.]+)([KMG])$/, a)) {
        v=a[1]+0; u=a[2];
        if (u=="K") v/=1000;
        else if (u=="G") v*=1000;
        print v;
      } else {
        print s+0;
      }
    }'
}
# 依 ymax 挑刻度
pick_ytick() {
  local y="$1"
  awk -v y="$y" 'BEGIN{
    if (y<=6)      print 1;
    else if (y<=20)print 2;
    else if (y<=50)print 5;
    else           print 10;
  }'
}

for bw in "${bandwidths[@]}"; do
    bw_mbps=$(bw_to_mbps "$bw")
    ymax=$(awk -v b="$bw_mbps" 'BEGIN{printf "%.0f", b*5}')
    # [ "$ymax" -le 0 ] && ymax=30
    ytick=$(pick_ytick "$ymax")


    # tcp

    python3 ./$script ${bw}-tcp-5g \
        --inputs 5G_With_Red:./$with_red_date/exp2/exp2-5g-tcp-red-80s-${bw}-server.pcap \
            5G_Without_Red:./$without_red_date/exp2/exp2-5g-tcp-ue-80s-${bw}-server.pcap \
        --port 5201   --win 1.0   --smooth 5  \
        --ymin 0 --ymax "$ymax" --ytick-step "$ytick" --outdir "$out_dir"

    python3 ./$script ${bw}-tcp-detnet \
        --inputs DetNet_With_Red:./$with_red_date/exp2/exp2-det-tcp-red-80s-${bw}-server.pcap \
            DetNet_Without_Red:./$without_red_date/exp2/exp2-det-tcp-ue-80s-${bw}-server.pcap \
        --port 5201   --win 1.0   --smooth 5  \
        --ymin 0 --ymax "$ymax" --ytick-step "$ytick" --outdir "$out_dir"

done