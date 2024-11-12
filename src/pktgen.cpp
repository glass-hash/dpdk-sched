#include "pktgen.h"

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
#include <iomanip>
#include <iostream>
#include <memory>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <fstream>

#include "clock.h"
#include "flows.h"
#include "log.h"

// Source/destination MACs
struct rte_ether_addr src_mac = {{0xb4, 0x96, 0x91, 0xa4, 0x02, 0xe9}};
struct rte_ether_addr dst_mac = {{0xb4, 0x96, 0x91, 0xa4, 0x04, 0x21}};

volatile bool quit;
struct config_t config;

static void signal_handler(int signum) {
  (void)signum;
  quit = true;
}

static const struct rte_eth_conf port_conf_default = {};

// Per worker configuration
struct worker_config_t {
  bool ready;

  struct rte_mempool* pool;
  uint16_t queue_id;

  bytes_t pkt_size;
  std::vector<flow_t> flows;

  const runtime_config_t* runtime;

  worker_config_t(struct rte_mempool* _pool, uint16_t _queue_id,
                  bytes_t _pkt_size, const std::vector<flow_t>& _flows,
                  const runtime_config_t* _runtime)
      : ready(false),
        pool(_pool),
        queue_id(_queue_id),
        pkt_size(_pkt_size),
        flows(_flows),
        runtime(_runtime) {}
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
      std::cerr << "Port " << port << " is not valid retval = " << retval << std::endl;
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
  // No Rx queues, just 1 Tx queue
  retval = rte_eth_dev_configure(port, 0, 1, &port_conf);
  if (retval != 0) {
      std::cerr << "rte_eth_dev_configure failed " << retval << std::endl;
      return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per TX worker port. */
  for (q = 0; q < 1; q++) {
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

static void generate_template_packet(byte_t* pkt, uint16_t size) {
  // Initialize Ethernet header
  struct rte_ether_hdr* ether_hdr = (struct rte_ether_hdr*)pkt;

  ether_hdr->s_addr = src_mac;
  ether_hdr->d_addr = dst_mac;
  ether_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  // Initialize the IPv4 header
  struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(ether_hdr + 1);

  ip_hdr->version_ihl = RTE_IPV4_VHL_DEF;
  ip_hdr->type_of_service = 0;
  ip_hdr->total_length = rte_cpu_to_be_16(size - sizeof(struct rte_ether_hdr));
  ip_hdr->packet_id = 0;
  ip_hdr->fragment_offset = 0;
  ip_hdr->time_to_live = 64;
  ip_hdr->next_proto_id = IPPROTO_UDP;
  ip_hdr->hdr_checksum = 0;  // Parameter
  ip_hdr->src_addr = 0;      // Parameter
  ip_hdr->dst_addr = 0;      // Parameter

  // Initialize the UDP header
  struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)(ip_hdr + 1);

  udp_hdr->src_port = 0;  // Parameter
  udp_hdr->dst_port = 0;  // Parameter
  udp_hdr->dgram_cksum = 0;
  udp_hdr->dgram_len = rte_cpu_to_be_16(
      size - (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)));

  // Fill payload with 1s.
  constexpr uint16_t max_pkt_size_no_crc = MAX_PKT_SIZE - 4;

  byte_t* payload = (byte_t*)(((char*)udp_hdr) + sizeof(struct rte_udp_hdr));
  bytes_t payload_size = max_pkt_size_no_crc - sizeof(struct rte_ether_hdr) -
                         sizeof(struct rte_ipv4_hdr) -
                         sizeof(struct rte_udp_hdr);
  for (bytes_t i = 0; i < payload_size; ++i) {
    payload[i] = 0xff;
  }
}

static void modify_template_packet(byte_t* pkt, const flow_t& flow) {
  struct rte_ether_hdr* ether_hdr = (struct rte_ether_hdr*)pkt;
  struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(ether_hdr + 1);
  struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)(ip_hdr + 1);
  ip_hdr->src_addr = flow.src_ip;
  ip_hdr->dst_addr = flow.dst_ip;
  udp_hdr->src_port = flow.src_port;
  udp_hdr->dst_port = flow.dst_port;
}

static void dump_flows_to_file() {
  bytes_t pkt_size_without_crc = config.pkt_size - 4;

  byte_t template_packet[MAX_PKT_SIZE];
  generate_template_packet(template_packet, pkt_size_without_crc);

  struct pcap_pkthdr header = {.ts = {.tv_sec = 0, .tv_usec = 0},
                               .caplen = (bpf_u_int32)pkt_size_without_crc,
                               .len = (bpf_u_int32)pkt_size_without_crc};

  pcap_t* p = NULL;
  pcap_dumper_t* pd = NULL;

  p = pcap_open_dead(DLT_EN10MB, 65535);
  assert(p);

  if ((pd = pcap_dump_open(p, DEFAULT_FLOWS_FILE)) == NULL) {
    fprintf(stderr, "Error opening savefile \"%s\" for writing: %s\n",
            DEFAULT_FLOWS_FILE, pcap_geterr(p));
    exit(7);
  }

  for (unsigned i = 0; i < config.tx.num_cores; i++) {
    const auto& flows = get_worker_flows(i);

    for (const auto& flow : flows) {
      modify_template_packet(template_packet, flow);
      pcap_dump((u_char*)pd, &header, template_packet);
    }
  }

  pcap_dump_close(pd);
  pcap_close(p);
}

static int tx_worker_main(void* arg) {
  worker_config_t* worker_config = (worker_config_t*)arg;

  bytes_t pkt_size_without_crc = worker_config->pkt_size - RTE_ETHER_CRC_LEN;
  size_t num_total_flows = worker_config->flows.size();

  struct rte_mbuf** mbufs = (struct rte_mbuf**)rte_malloc(
      "mbufs", sizeof(struct rte_mbuf*) * NUM_SAMPLE_PACKETS, 0);
  if (mbufs == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot allocate mbufs\n");
  }

  byte_t template_packet[MAX_PKT_SIZE];
  generate_template_packet(template_packet, pkt_size_without_crc);

  flow_t* flows =
      (flow_t*)rte_malloc("flows", num_total_flows * sizeof(flow_t), 0);

  for (uint32_t i = 0; i < num_total_flows; i++) {
    flows[i] = worker_config->flows[i];
  }

  // Prefill buffers with template packet.
  for (uint32_t i = 0; i < NUM_SAMPLE_PACKETS; i++) {
    mbufs[i] = rte_pktmbuf_alloc(worker_config->pool);

    if (unlikely(mbufs[i] == nullptr)) {
      rte_exit(EXIT_FAILURE, "Failed to create mbuf\n");
    }

    rte_pktmbuf_append(mbufs[i], pkt_size_without_crc);
    rte_memcpy(rte_pktmbuf_mtod(mbufs[i], void*), template_packet,
               pkt_size_without_crc);
  }

  uint32_t mbuf_burst_offset = 0;

  bytes_t total_pkt_size = 0;
  uint64_t num_total_tx = 0;

  uint16_t queue_id = worker_config->queue_id;

  // Run until the application is killed
  while (likely(!quit)) {
    rte_mbuf** mbuf_burst = mbufs + mbuf_burst_offset;
    mbuf_burst_offset = (mbuf_burst_offset + BURST_SIZE) % NUM_SAMPLE_PACKETS;

    // Generate a burst of packets
    for (int i = 0; i < BURST_SIZE; i++) {
      rte_mbuf* pkt = mbuf_burst[i % NUM_SAMPLE_PACKETS];
      total_pkt_size += pkt->pkt_len;

      struct rte_ether_hdr* ether_hdr =
          rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
      struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(ether_hdr + 1);
      ip_hdr->next_proto_id = IPPROTO_UDP;

      // HACK(sadok): Increase refcnt to avoid freeing.
      pkt->refcnt = MIN_NUM_MBUFS;
    }

    uint16_t num_tx =
        rte_eth_tx_burst(config.tx.port, queue_id, mbuf_burst, BURST_SIZE);

    num_total_tx += num_tx;
  }

  rte_free(mbufs);
  std::cout << "worker ending" << std::endl;
  return 0;
}

static void wait_port_up(uint16_t port_id) {
  struct rte_eth_link link;
  link.link_status = ETH_LINK_DOWN;

  LOG("Waiting for port %u...", port_id);

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
  LOG("Port %" PRIu8, port_id);
  LOG("    ipackets: %" PRIu64, stats.ipackets);
  LOG("    opackets: %" PRIu64, stats.opackets);
  LOG("    ibytes: %" PRIu64, stats.ibytes);
  LOG("    obytes: %" PRIu64, stats.obytes);
  LOG("    imissed: %" PRIu64, stats.imissed);
  LOG("    oerrors: %" PRIu64, stats.oerrors);
  LOG("    rx_nombuf: %" PRIu64, stats.rx_nombuf);
  LOG();

  LOG("==== Extended Statistics ====");
  int num_xstats = rte_eth_xstats_get(port_id, NULL, 0);
  struct rte_eth_xstat xstats[max_num_stats];
  if (rte_eth_xstats_get(port_id, xstats, num_xstats) != num_xstats) {
    WARNING("Cannot get xstats (port %u)", port_id);
    return;
  }
  struct rte_eth_xstat_name xstats_names[max_num_stats];
  if (rte_eth_xstats_get_names(port_id, xstats_names, num_xstats) !=
      num_xstats) {
    WARNING("Cannot get xstats (port %u)", port_id);
    return;
  }
  for (int i = 0; i < num_xstats; ++i) {
    LOG("%s: %" PRIu64, xstats_names[i].name, xstats[i].value);
  }
  LOG();
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
      "mbufs pools", sizeof(struct rte_mempool*) * config.tx.num_cores, 0);

  for (unsigned i = 0; i < config.tx.num_cores; i++) {
    unsigned lcore_id = config.tx.cores[i];
    mbufs_pools[i] = create_mbuf_pool(lcore_id);
  }

  std::cout << "tx port is " << config.tx.port << std::endl;
  if (port_init(config.tx.port)) {
    rte_exit(EXIT_FAILURE, "Cannot init tx port %" PRIu16 "\n", 0);
  }

  generate_unique_flows_per_worker();

  if (config.dump_flows_to_file) {
    dump_flows_to_file();
  }

  std::vector<std::unique_ptr<worker_config_t>> workers_configs(
      config.tx.num_cores);

  for (unsigned i = 0; i < config.tx.num_cores; i++) {
    unsigned lcore_id = config.tx.cores[i];
    unsigned queue_id = i;

    workers_configs[i] = std::make_unique<worker_config_t>(
        mbufs_pools[i], queue_id, config.pkt_size, get_worker_flows(i),
        &config.runtime);

    std::cout << "Launching on core " << lcore_id << std::endl;
    rte_eal_remote_launch(
        tx_worker_main, static_cast<void*>(workers_configs[i].get()), lcore_id);
  }

  // We no longer need the arrays. This doesn't free the mbufs themselves
  // though, we still need them.
  rte_free(mbufs_pools);
  wait_port_up(config.tx.port);

  LOG("Waiting for workers to finish...");
  // Wait for all processes to complete
  rte_eal_mp_wait_lcore();

  get_port_stats(0);

  rte_eal_cleanup();

  return 0;
}
