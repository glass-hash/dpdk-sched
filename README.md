# DPDK traffic generator

## Dependencies

| Application | Version |
| ----------- | ------- |
| cmake       | >=3.16  |
| meson       | 1.3.1   |
| DPDK        | 22.11   |

## Installation instructions

1. Run `setup.sh` to install dependencies locally.
   - **Note:** you only need to run this once to install the dependencies.
2. Build with meson by running `build.sh`.
3. Source the paths file: `source paths.sh`.
4. Run `Debug/bin/pktgen` or `Release/bin/pktgen`.

## Running

Like every DPDK application, one must go through the EAL arguments first, and only then consider the application specific arguments, like such:

```
$ sudo ./Debug/bin/pktgen $EAL_ARGS -- $PKTGEN_ARGS
```

To bring up the help menu from pktgen specifically, one can use a testing EAL configuration:

```
$ sudo ./Debug/bin/pktgen \
    --no-huge \
    --no-shconf \
    --vdev "net_tap0,iface=test_rx" \
    --vdev "net_tap1,iface=test_tx" \
    -- \
    --help
```

## Testing

Example pktgen configuration (for testing purposes):

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
    --crc-bits 16 \
    --seed 0
```