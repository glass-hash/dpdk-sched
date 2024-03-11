#!/bin/bash

set -e

if [ $# -eq 0 ]; then
    echo "Usage: ./dump_flows.sh <number of flows> [seed]"
    exit 1
fi

flows=$1
seed=${2:-'0'}

echo "Flows $flows"
echo "Seed $seed"

./build.sh
echo quit | sudo ./Debug/bin/pktgen \
    -m 8192 \
    --no-huge \
    --no-shconf \
    --vdev "net_tap0,iface=test_rx" \
    --vdev "net_tap1,iface=test_tx" \
    -- \
    --total-flows $flows \
    --pkt-size 64 \
    --tx 1 \
    --rx 0 \
    --tx-cores 1 \
    --seed $seed \
    --dump-flows-to-file

sudo chown $USER:$USER flows.pcap
mv flows.pcap flows_${flows}_seed_${seed}.pcap
