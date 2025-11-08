#!/bin/bash

# ...existing code...
# 參數
DURATION=70
INTERVAL=10
FRONT_TAIL=10

GROUP_B=(enp0s8)
GROUP_A=(enp0s9)

for IFACE in "${GROUP_A[@]}" "${GROUP_B[@]}"; do
    sudo tc qdisc add dev $IFACE root handle 1: netem delay 0ms 2>/dev/null || true
done

# 先讓前段正常運作 FRONT_TAIL 秒
sleep $FRONT_TAIL

# 中間要做切換的總時間（排除前後各 FRONT_TAIL 秒）
MIDDLE=$((DURATION - 2 * FRONT_TAIL))
if (( MIDDLE > 0 )); then
    LOOPS=$((MIDDLE / INTERVAL))
    for ((i=1; i<=LOOPS; i++)); do
        if ((i % 2 == 0)); then
            for IFACE in "${GROUP_B[@]}"; do
                sudo tc qdisc change dev $IFACE root netem loss 0%
            done

            for IFACE in "${GROUP_A[@]}"; do
                sudo tc qdisc change dev $IFACE root netem loss 100%
            done

        else
            for IFACE in "${GROUP_A[@]}"; do
                sudo tc qdisc change dev $IFACE root netem loss 0%
            done
            for IFACE in "${GROUP_B[@]}"; do
                sudo tc qdisc change dev $IFACE root netem loss 100%
            done

        fi
        sleep $INTERVAL
    done
else
    echo "DURATION 太短，無中間切換 (MIDDLE=$MIDDLE)"
fi

# 全部恢復（loss 0%）並保持後段正常 FRONT_TAIL 秒
for IFACE in "${GROUP_A[@]}" "${GROUP_B[@]}"; do
    sudo tc qdisc change dev $IFACE root netem loss 0%
done
sleep $FRONT_TAIL
echo "全部恢復"
