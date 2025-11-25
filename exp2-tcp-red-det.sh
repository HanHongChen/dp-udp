#!/bin/bash

#free5gc
# ssh vagrant@140.113.208.90 -p 2223 'sudo docker exec ueransim /bin/bash /ueransim/dp-udp/exp/script/iperf.sh' &
ssh vagrant@140.113.208.90 -p 2223 'sudo docker exec ue /bin/bash /free-ran-ue/dp-udp/exp/script/tcp_iperf.sh' &
#sdn
ssh ubuntu@140.113.208.90 -p 10022 "echo '0000' | sudo -S bash /home/ubuntu/Desktop/chh/Experiment/detnet-controller-topo/tc_loop.sh" &

wait
echo "finish"