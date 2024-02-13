# DPDK traffic generator

## Dependencies

| Application | Version |
| ----------- | ------- |
| DPDK        | 22.11   |
| meson       | 1.3.1   |

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