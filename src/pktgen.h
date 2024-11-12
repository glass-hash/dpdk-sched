#ifndef PKTGEN_SRC_PKTGEN_H_
#define PKTGEN_SRC_PKTGEN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_udp.h>
#include <stdbool.h>
#include <stdint.h>

#define BURST_SIZE 32
#define MBUF_CACHE_SIZE 512
#define MIN_NUM_MBUFS 8192
#define DESC_RING_SIZE 1024
#define NUM_SAMPLE_PACKETS (2 * DESC_RING_SIZE)
#define DEFAULT_FLOWS_FILE "flows.pcap"

#define MIN_FLOWS_NUM 1

#define MIN_PKT_SIZE ((bytes_t)64)    // With CRC
#define MAX_PKT_SIZE ((bytes_t)1518)  // With CRC

typedef uint64_t bits_t;
typedef uint64_t bytes_t;

typedef uint8_t bit_t;
typedef uint8_t byte_t;

typedef uint64_t time_ns_t;
typedef uint64_t time_us_t;
typedef uint64_t time_ms_t;
typedef uint64_t time_s_t;

#define NS_TO_S(T) (((double)(T)) / 1e9)

struct flow_t {
  rte_be32_t src_ip;
  rte_be32_t dst_ip;
  rte_be16_t src_port;
  rte_be16_t dst_port;
};

typedef double rate_gbps_t;
typedef double rate_mbps_t;

typedef double rate_mpps_t;

struct runtime_config_t {
  bool running;
  uint64_t update_cnt;

  // Information for each TX worker
  rate_gbps_t rate_per_core;
};

struct config_t {
  bool dump_flows_to_file;
  uint32_t num_flows;
  time_ns_t exp_time;
  bytes_t pkt_size;
  rate_gbps_t rate;

  struct {
    uint16_t port;
    uint16_t num_cores;
    uint16_t cores[RTE_MAX_LCORE];
  } tx;

  struct runtime_config_t runtime;
};

extern struct config_t config;

void config_init(int argc, char **argv);
void config_print();
void config_print_usage(char **argv);

struct stats_t {
  uint64_t tx_pkts;
};

struct stats_t get_stats();

#ifdef __cplusplus
}
#endif

#endif  // PKTGEN_SRC_PKTGEN_H_
