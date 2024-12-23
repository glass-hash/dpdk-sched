# DPDK based scheduler

## Dependencies

| Application | Version |
| ----------- | ------- |
| DPDK        | 20.11   |

## Compilation instructions
1. `meson setup build`
2. `cd build`
3. `ninja`

## Running

`sudo ./build/dpdk_sched -m 8192 -l 0-1 -- --tx 0 --num-cores 1 --flows-per-core 1 --timeout=10`
