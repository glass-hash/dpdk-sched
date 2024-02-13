# SyNAPSE traffic generator

## Info

Pktgen uses **DPDK 22.11** to generate traffic.

## Testing

```
$ sudo ./Debug/bin/pktgen \
    -m 8192 \
    --no-huge \
    --no-shconf \
    --vdev "net_tap0,iface=test_rx" \
    --vdev "net_tap1,iface=test_tx" \
    -- \
    --total-flows 4 \
    --tx 1 \
    --rx 0 \
    --tx-cores 1 \
    --crc-unique-flows \
    --crc-bits 16
```