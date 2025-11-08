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
    SUFFIX=""   # exp1 沒有 det/5g
elif [[ "$1" =~ ^-exp2$ ]] && [[ "$2" =~ ^[1-3]$ ]] && [[ "$3" == "det" || "$3" == "5g" ]]; then
    EXP_TAG="exp2"
    PANE_COUNT="$2"
    SUFFIX="$3" # exp2 有 det/5g
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

SESSION="dpudp_client"
tmux kill-session -t $SESSION 2>/dev/null || true

# 1. Create a new tmux session with a single window/pane (pane 0.0, leftmost)
tmux new-session -d -s $SESSION

# 2. Immediately execute the command in the left pane (pane 0.0)
tmux send-keys -t $SESSION:0.0 "./build/dp-udp client -c config/client_udp.yaml" C-m
tmux select-pane -t $SESSION:0.0

if [[ "$PANE_COUNT" -ge 2 ]]; then
    # 3. Split vertically to create pane 0.1
    tmux split-window -v -l 15 -t $SESSION:0.0
    # 4. Execute command in the middle pane (pane 0.1)
    # --bind-dev dpUdpTunClient
    # iperf3 -c 192.180.20.10 -B 192.180.10.10 -u -l 1150
    tmux send-keys -t $SESSION:0.1 "iperf3 -c 192.180.20.10 -B 192.180.10.10 -u -t 1 -b 10M " C-m
    tmux select-pane -t $SESSION:0.1
fi

if [[ "$PANE_COUNT" -ge 3 ]]; then
    # 5. Split horizontally again to create pane 0.2
    tmux split-window -h -l 30 -t $SESSION:0.1
    # 6. Run tcpdump in the rightmost pane (pane 0.2)
    if [[ "$EXP_TAG" == "exp2" ]]; then
        # exp2: tcpdump 檔名包含 det/5g
        tmux send-keys -t $SESSION:0.2 "tcpdump -i dpUdpTunClient udp -w $EXP_DIR/${EXP_TAG}-$SUFFIX-red-80s-5M-client.pcap" C-m
    else
        # exp1: tcpdump 檔名不包含 det/5g
        tmux send-keys -t $SESSION:0.2 "tcpdump -i dpUdpTunClient udp -w $EXP_DIR/${EXP_TAG}-red-ul-80s-5M-client.pcap" C-m
    fi
    tmux select-pane -t $SESSION:0.1
fi

# Attach to tmux session
tmux attach -t $SESSION

# ====== tmux usage tips ======
# Ctrl+b o        switch to the next pane
# Ctrl+b q        show pane numbers
# Ctrl+b <arrow>  move between panes
# =============================