IFACE0=enp0s9
IFACE1=enp0s8
sudo tc qdisc add dev $IFACE0 root handle 1: netem delay 0ms 2>/dev/null || true
sudo tc qdisc add dev $IFACE1 root handle 1: netem delay 0ms 2>/dev/null || true

sudo tc qdisc change dev $IFACE0 root netem loss 100%   
sudo tc qdisc change dev $IFACE1 root netem loss 100% 
# sudo tc qdisc change dev $IFACE2 root netem loss 100%   
# sudo tc qdisc change dev $IFACE3 root netem loss 100% 
sleep 10
# sudo tc qdisc change dev $IFACE1 root netem loss 0%   
# sudo tc qdisc change dev $IFACE0 root netem loss 100% 
# sleep 10
# sudo tc qdisc change dev $IFACE0 root netem loss 0%   
# sudo tc qdisc change dev $IFACE1 root netem loss 100% 
# sleep 10
# sudo tc qdisc change dev $IFACE1 root netem loss 0%   
# sudo tc qdisc change dev $IFACE0 root netem loss 100% 
# sleep 10
# sudo tc qdisc change dev $IFACE0 root netem loss 0%   
# sudo tc qdisc change dev $IFACE1 root netem loss 100% 
# sleep 10
sudo tc qdisc change dev $IFACE1 root netem loss 0%   
sudo tc qdisc change dev $IFACE0 root netem loss 0% 
