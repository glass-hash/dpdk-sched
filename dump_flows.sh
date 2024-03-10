#!/bin/bash

set -e

flows=$1

if [ $# -eq 0 ]; then
    echo "Usage: ./dump_flows.sh <number of flows>"
    exit 1
fi

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
    --crc-unique-flows \
    --crc-bits 16 \
    --seed 0 \
    --dump-flows-to-file
