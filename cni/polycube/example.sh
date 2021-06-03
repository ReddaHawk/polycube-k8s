#!/bin/sh
sudo ip netns del ns1
sudo rm -rf /var/lib/cni/networks/mynet/
sudo ip netns add ns1

echo "Ready to call the step4 example"
sudo CNI_COMMAND=ADD CNI_CONTAINERID=ns1provaprova CNI_NETNS=/var/run/netns/ns1 CNI_IFNAME=eth10 CNI_PATH=/home/ubuntu/plugins/bin ./plugins/bin/polycube < config
