#!/bin/bash

TODAY=$(date +%Y%m%d)

# Default values
EXP_TAG="exp1"
PANE_COUNT=3
SUFFIX=""

# Parse arguments
if [[ "$1" =~ ^-exp1$ ]] && [[ "$2" =~ ^[1-3]$ ]]; then
    EXP_TAG="exp1"
    PANE_COUNT="$2"
    SUFFIX=""    # exp1 沒有 det/5g
elif [[ "$1" =~ ^-exp2$ ]] && [[ "$2" =~ ^[1-3]$ ]] && [[ "$3" == "det" || "$3" == "5g" ]]; then
    EXP_TAG="exp2"
    PANE_COUNT="$2"
    SUFFIX="$3"  # exp2 有 det/5g
else
    echo "Usage:"
    echo "  $0 -exp1 3"
    echo "  $0 -exp2 2 det"
    echo "  $0 -exp2 3 5g"
    exit 1
fi

EXP_DIR="exp/$TODAY/$EXP_TAG"
[ ! -d "$EXP_DIR" ] && mkdir -p "$EXP_DIR"

if ! command -v tmux &> /dev/null; then
    echo "tmux is not installed, please install tmux first."
    exit 1
fi

SESSION="dpudp_server"
tmux kill-session -t $SESSION 2>/dev/null || true

tmux new-session -d -s $SESSION
tmux send-keys -t $SESSION:0.0 "sudo ./build/dp-udp server -c ./config/server_udp.yaml" C-m
tmux select-pane -t $SESSION:0.0

if [[ "$PANE_COUNT" -ge 2 ]]; then
    tmux split-window -v -l 15 -t $SESSION:0.0
    sleep 0.2
    tmux send-keys -t $SESSION:0.1 "iperf3 -s -B 192.180.20.10" C-m
    tmux select-pane -t $SESSION:0.1
fi

if [[ "$PANE_COUNT" -ge 3 ]]; then
    tmux split-window -h -l 30 -t $SESSION:0.1
    if [[ "$EXP_TAG" == "exp2" ]]; then
        # exp2: tcpdump 檔名包含 det/5g
        tmux send-keys -t $SESSION:0.2 "sudo tcpdump -i dpUdpTunServer udp -w $EXP_DIR/${EXP_TAG}-$SUFFIX-red-80s-5M-server.pcap" C-m
    else
        # exp1: tcpdump 檔名不包含 det/5g
        tmux send-keys -t $SESSION:0.2 "sudo tcpdump -i dpUdpTunServer udp -w $EXP_DIR/${EXP_TAG}-red-ul-80s-5M-server.pcap" C-m
    fi
    tmux select-pane -t $SESSION:0.2
fi

tmux attach -t $SESSION

# ====== tmux usage tips ======
# Ctrl+b o        switch to the next pane
# Ctrl+b q        show pane numbers
# Ctrl+b <arrow>  move between panes
# =============================