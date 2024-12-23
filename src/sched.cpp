#include <pcap.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_udp.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "clock.h"
#include "flows.h"
#include "log.h"
#include "pktgen.h"

volatile bool quit;
struct config_t config;

static void signal_handler(int signum) {
  (void)signum;
  quit = true;
}

static const struct rte_eth_conf port_conf_default = {};

// Per worker configuration
struct worker_config_t {
  struct rte_mempool* pool;
  uint16_t queue_id;
  uint16_t flows_per_core;
  worker_config_t(struct rte_mempool* _pool, uint16_t _queue_id,
                  uint16_t _flows_per_core)
      : pool(_pool), queue_id(_queue_id), flows_per_core(_flows_per_core) {}
};

static inline int port_init(uint16_t port) {
  struct rte_eth_conf port_conf = port_conf_default;
  uint16_t nb_txd = DESC_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;

  retval = rte_eth_dev_is_valid_port(port);
  if (retval != 1) {
    std::cerr << "Port " << port << " is not valid retval = " << retval
              << std::endl;
    return -1;
  }

  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
             port, strerror(-retval));
  }

  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM)
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM;

  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_OUTER_UDP_CKSUM)
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_OUTER_UDP_CKSUM;

  /* Configure the Ethernet device. */
  // No Rx queues
  retval = rte_eth_dev_configure(port, 0, config.num_cores, &port_conf);
  if (retval != 0) {
    std::cerr << "rte_eth_dev_configure failed " << retval << std::endl;
    return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per TX worker. */
  for (q = 0; q < config.num_cores; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                    rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0) {
      std::cerr << "rte_eth_tx_queue_setup failed " << retval << std::endl;
      return retval;
    }
  }

  // Reset all stats.
  retval = rte_eth_stats_reset(port);
  if (retval != 0) {
    std::cerr << "rte_eth_stats_reset failed " << retval << std::endl;
    return retval;
  }

  retval = rte_eth_xstats_reset(port);
  if (retval != 0) {
    std::cerr << "rte_eth_xstats_reset failed " << retval << std::endl;
    return retval;
  }

  /* Start the port. */
  retval = rte_eth_dev_start(port);
  if (retval < 0) {
    std::cerr << "rte_eth_xstats_reset failed " << retval << std::endl;
    return retval;
  }

  return 0;
}

struct rte_mempool* create_mbuf_pool(unsigned lcore_id) {
  unsigned mbuf_entries = MBUF_CACHE_SIZE + BURST_SIZE + NUM_SAMPLE_PACKETS;
  mbuf_entries = RTE_MAX(mbuf_entries, (unsigned)MIN_NUM_MBUFS);

  /* Creates a new mempool in memory to hold the mbufs. */
  char MBUF_POOL_NAME[20];
  sprintf(MBUF_POOL_NAME, "MBUF_POOL_%u", lcore_id);

  unsigned socket_id = rte_lcore_to_socket_id(lcore_id);

  struct rte_mempool* mbuf_pool =
      rte_pktmbuf_pool_create(MBUF_POOL_NAME, mbuf_entries, MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);

  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Failed to create mbuf pool\n");
  }

  return mbuf_pool;
}

static int tx_worker_main(void* arg) {
  worker_config_t* worker_config = (worker_config_t*)arg;
  const uint16_t port_id = config.port;
  const uint16_t queue_id = worker_config->queue_id;
  const uint16_t flows_per_core = worker_config->flows_per_core;

  // Pre-allocate burst of mbufs
  struct rte_mbuf* tx_burst[BURST_SIZE];
  for (int i = 0; i < BURST_SIZE; i++) {
    // Allocate new mbuf for each packet
    tx_burst[i] = rte_pktmbuf_alloc(worker_config->pool);
    if (unlikely(tx_burst[i] == nullptr)) {
      rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
    }
  }

  uint32_t flow_idx_start = queue_id * flows_per_core;
  uint32_t flow_idx_end = flow_idx_start + flows_per_core;
  uint32_t flow_idx = flow_idx_start;

  while (likely(!quit)) {
    const flow_t& current_flow = flows[flow_idx];
    for (int i = 0; i < BURST_SIZE; i++) {
      // Append and copy data
      rte_pktmbuf_reset(tx_burst[i]);
      uint8_t* packet =
          (uint8_t*)rte_pktmbuf_append(tx_burst[i], current_flow.size);
      if (packet == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to append mbuf\n");
      }
      rte_memcpy(packet, current_flow.pkt_buf, current_flow.size);
    }

    // Send burst
    rte_eth_tx_burst(port_id, queue_id, tx_burst, BURST_SIZE);

    flow_idx++;
    if (flow_idx == flow_idx_end) {
      flow_idx = flow_idx_start;
    }
  }

  for (uint16_t i = 0; i < BURST_SIZE; i++) {
    rte_pktmbuf_free(tx_burst[i]);
  }

  return 0;
}

static void wait_port_up(uint16_t port_id) {
  struct rte_eth_link link;
  link.link_status = ETH_LINK_DOWN;

  // LOG("Waiting for port %u...", port_id);
  LOG("Waiting for port " << port_id);

  while (link.link_status == ETH_LINK_DOWN) {
    int retval = rte_eth_link_get(port_id, &link);
    if (retval != 0) {
      rte_exit(EXIT_FAILURE, "Error getting port status (port %u) info: %s\n",
               port_id, strerror(-retval));
    }
    sleep_ms(100);
  }
}

static void get_port_stats(uint16_t port_id) {
  struct rte_eth_stats stats;

  constexpr uint16_t max_num_stats = 1024;

  rte_eth_stats_get(port_id, &stats);

  LOG("==== Statistics ====");
  LOG("Port " << port_id);
  LOG("    ipackets: " << stats.ipackets);
  LOG("    opackets: " << stats.opackets);
  LOG("    ibytes: " << stats.ibytes);
  LOG("    obytes: " << stats.obytes);
  LOG("    imissed: " << stats.imissed);
  LOG("    oerrors: " << stats.oerrors);
  LOG("    rx_nombuf: " << stats.rx_nombuf);
  std::ofstream statsFile("schedTxStats.csv");
  statsFile << stats.obytes << "," << stats.opackets << std::endl;
  statsFile.close();

  LOG("==== Extended Statistics ====");
  int num_xstats = rte_eth_xstats_get(port_id, NULL, 0);
  struct rte_eth_xstat xstats[max_num_stats];
  if (rte_eth_xstats_get(port_id, xstats, num_xstats) != num_xstats) {
    WARNING("Cannot get xstats for port " << port_id);
    return;
  }
  struct rte_eth_xstat_name xstats_names[max_num_stats];
  if (rte_eth_xstats_get_names(port_id, xstats_names, num_xstats) !=
      num_xstats) {
    WARNING("Cannot get xstats for port " << port_id);
    return;
  }
  for (int i = 0; i < num_xstats; ++i) {
    LOG(xstats_names[i].name << " " << xstats[i].value);
  }
}

int main(int argc, char* argv[]) {
  quit = false;

  signal(SIGINT, signal_handler);
  signal(SIGQUIT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  }
  argc -= ret;
  argv += ret;

  // Parse command-line arguments
  config_init(argc, argv);
  config_print();

  struct rte_mempool** mbufs_pools = (struct rte_mempool**)rte_malloc(
      "mbufs pools", sizeof(struct rte_mempool*) * config.num_cores, 0);

  for (unsigned i = 0; i < config.num_cores; i++) {
    unsigned lcore_id = config.cores[i];
    mbufs_pools[i] = create_mbuf_pool(lcore_id);
  }

  if (port_init(config.port)) {
    rte_exit(EXIT_FAILURE, "Cannot init tx port %" PRIu16 "\n", 0);
  }

  generate_flows();

  std::vector<std::unique_ptr<worker_config_t>> workers_configs(
      config.num_cores);

  for (unsigned i = 0; i < config.num_cores; i++) {
    unsigned lcore_id = config.cores[i];
    workers_configs[i] = std::make_unique<worker_config_t>(
        mbufs_pools[i], i, config.flows_per_core);

    std::cout << "Launching on core " << lcore_id << std::endl;
    rte_eal_remote_launch(
        tx_worker_main, static_cast<void*>(workers_configs[i].get()), lcore_id);
  }

  // We no longer need the arrays. This doesn't free the mbufs themselves
  // though, we still need them.
  rte_free(mbufs_pools);
  wait_port_up(config.port);

  uint64_t cur_time = 0;
  while (!quit) {
    sleep_ms(1000);
    cur_time++;
    if (cur_time == config.timeout) {
      quit = true;
    }
  }
  LOG("Waiting for workers to finish...");
  // Wait for all processes to complete
  rte_eal_mp_wait_lcore();

  get_port_stats(config.port);

  free_flows();
  rte_eal_cleanup();

  return 0;
}
