#!/bin/bash

TODAY=$(date +%Y%m%d)
BASE_DIR="exp/$TODAY"

if ! command -v tmux &> /dev/null; then
    echo "tmux is not installed, please install tmux first."
    exit 1
fi

SESSION="exp_server"
tmux kill-session -t $SESSION 2>/dev/null || true

if [[ "$1" == "-exp1" ]]; then
    EXP_DIR="$BASE_DIR/exp1"
    [ ! -d "$EXP_DIR" ] && mkdir -p "$EXP_DIR"
    tmux new-session -d -s $SESSION
    tmux send-keys -t $SESSION:0.0 "iperf3 -s -B 192.168.58.20" C-m
    tmux split-window -h -l 40 -t $SESSION:0.0
    tmux send-keys -t $SESSION:0.1 "iperf3 -s -B 192.168.59.20" C-m
    tmux split-window -v -l 15 -t $SESSION:0.1
    tmux send-keys -t $SESSION:0.2 "sudo tcpdump -i enp0s8 udp -w $EXP_DIR/exp1-ue1-ul-60s-server.pcap" C-m
    tmux split-window -v -l 15 -t $SESSION:0.2
    tmux send-keys -t $SESSION:0.3 "sudo tcpdump -i enp0s9 udp -w $EXP_DIR/exp1-ue2-ul-60s-server.pcap" C-m
    tmux select-pane -t $SESSION:0.3
    tmux attach -t $SESSION
    exit 0
fi

if [[ "$1" == "-exp2" ]] && ([[ "$2" == "det" ]] || [[ "$2" == "5g" ]]); then
    SUFFIX="$2"
    EXP_DIR="$BASE_DIR/exp2"
    [ ! -d "$EXP_DIR" ] && mkdir -p "$EXP_DIR"
    tmux new-session -d -s $SESSION
    tmux send-keys -t $SESSION:0.0 "iperf3 -s -B 192.168.58.20" C-m
    tmux split-window -h -l 40 -t $SESSION:0.0
    tmux send-keys -t $SESSION:0.1 "sudo tcpdump -i enp0s8 udp -w $EXP_DIR/exp2-${SUFFIX}-ue-60s-server.pcap" C-m
    tmux select-pane -t $SESSION:0.1
    tmux attach -t $SESSION
    exit 0
fi

echo "Usage: $0 -exp1"
echo "       $0 -exp2 <det|5g>"
exit 1