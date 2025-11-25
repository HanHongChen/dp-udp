#!/bin/bash

#free5gc
# ssh vagrant@140.113.208.90 -p 2223 '
# sudo docker exec ueransim /bin/bash /ueransim/dp-udp/exp/script/iperf.sh &
# sudo /home/vagrant/dp-udp/exp/script/tc_loop_free5gc.sh &
# wait
# echo "finish"
# '

# free-ran-ue on free5gc vm docker container
ssh vagrant@140.113.208.90 -p 2223 '
sudo docker exec ue /bin/bash /free-ran-ue/dp-udp/exp/script/iperf.sh &
sudo /home/vagrant/dp-udp/exp/script/tc_loop_free5gc.sh &
wait
echo "finish"
'

#free-ran-gnb on ue-lab vm not in a docker
# ssh vagrant@140.113.208.90 -p 2233 '/home/vagrant/dp-udp/exp/script/iperf.sh' &
# ssh vagrant@140.113.208.90 -p 2223 '
# sudo /home/vagrant/dp-udp/exp/script/tc_loop_free5gc.sh &'

# wait
# echo "finish"
