#!/bin/bash

TODAY=$(date +%Y%m%d)
EXP_DIR="exp/$TODAY/exp1"
[ ! -d "$EXP_DIR" ] && mkdir -p "$EXP_DIR"

if ! command -v tmux &> /dev/null; then
    echo "tmux is not installed, please install tmux first."
    exit 1
fi

SESSION="exp_ue"
tmux kill-session -t $SESSION 2>/dev/null || true

tmux new-session -d -s $SESSION
tmux send-keys -t $SESSION:0.0 "tcpdump -i ueTun1 tcp -w $EXP_DIR/exp1-tcp-ue1-ul-80s-20M-client.pcap" C-m
tmux split-window -h -l 40 -t $SESSION:0.0
# tmux send-keys -t $SESSION:0.1 "tcpdump -i ueTun2 udp -w $EXP_DIR/exp1-ue2-ul-80s-20M-client.pcap" C-m
# tmux split-window -v -l 15 -t $SESSION:0.1
# tmux send-keys -t $SESSION:0.1 "iperf3 -c 192.168.58.20 -B 10.60.0.1 -u -t 80 -b 20M & iperf3 -c 192.168.59.20 -B 10.63.0.1 -t 80 -b 20M -u &" C-m
tmux send-keys -t $SESSION:0.1 "iperf3 -c 192.168.58.20 -B 10.60.0.1 -t 80 -b 20M" C-m
tmux select-pane -t $SESSION:0.1
tmux attach -t $SESSION

# ====== tmux usage tips ======
# Ctrl+b o        switch to next pane
# Ctrl+b q        show pane numbers
# Ctrl+b <arrow>  move between panes
# =============================