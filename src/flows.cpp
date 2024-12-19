#include <rte_common.h>
#include <rte_random.h>

#include <iostream>
#include <unordered_set>
#include <vector>

#include "log.h"
#include "pktgen.h"

struct rte_ether_addr src_mac = {{0xb4, 0x96, 0x91, 0xa4, 0x02, 0xe9}};
struct rte_ether_addr dst_mac = {{0xb4, 0x96, 0x91, 0xa4, 0x04, 0x21}};

std::vector<flow_t> flows;

flow_t generate_flow(uint32_t index, uint16_t pkt_size) {
  flow_t new_flow;
  uint32_t base_ip = 0xC0A80000;
  new_flow.src_ip = rte_cpu_to_be_32(0x0A000001);
  new_flow.dst_ip = rte_cpu_to_be_32(base_ip + index);
  new_flow.src_port = rte_cpu_to_be_16(8080);
  new_flow.dst_port = rte_cpu_to_be_16(80);
  new_flow.pkt_buf = (uint8_t*)malloc(pkt_size * sizeof(uint8_t));
  if (new_flow.pkt_buf == NULL) {
    std::cerr << "Failed to allocate memory from malloc" << std::endl;
    exit(0);
  }
  new_flow.size = pkt_size;

  uint16_t pkt_size_no_crc = pkt_size - RTE_ETHER_CRC_LEN;

  // Setup packet headers
  struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)new_flow.pkt_buf;
  struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
  struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)(ip_hdr + 1);

  // Ethernet header
  eth_hdr->s_addr = src_mac;
  eth_hdr->d_addr = dst_mac;
  eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  // IP header
  ip_hdr->version_ihl = RTE_IPV4_VHL_DEF;
  ip_hdr->type_of_service = 0;
  ip_hdr->total_length =
      rte_cpu_to_be_16(pkt_size_no_crc - sizeof(struct rte_ether_hdr));
  ip_hdr->packet_id = 0;
  ip_hdr->fragment_offset = 0;
  ip_hdr->time_to_live = 64;
  ip_hdr->next_proto_id = IPPROTO_UDP;
  ip_hdr->src_addr = new_flow.src_ip;
  ip_hdr->dst_addr = new_flow.dst_ip;
  ip_hdr->hdr_checksum = 0;
  ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

  // UDP header
  udp_hdr->src_port = new_flow.src_port;
  udp_hdr->dst_port = new_flow.dst_port;
  udp_hdr->dgram_len =
      rte_cpu_to_be_16(pkt_size_no_crc - (sizeof(struct rte_ether_hdr) +
                                          sizeof(struct rte_ipv4_hdr)));
  udp_hdr->dgram_cksum = 0;

  new_flow.size = pkt_size_no_crc;

  byte_t* payload = (byte_t*)(((char*)udp_hdr) + sizeof(struct rte_udp_hdr));
  bytes_t payload_size = pkt_size_no_crc - sizeof(struct rte_ether_hdr) -
                         sizeof(struct rte_ipv4_hdr) -
                         sizeof(struct rte_udp_hdr);
  for (bytes_t i = 0; i < payload_size; ++i) {
    payload[i] = 0xff;
  }
  return new_flow;
}

void generate_flows() {
  uint32_t total_flows = config.flows_per_core * config.num_cores;
  LOG("Generating " << total_flows << " flows");
  uint32_t i = 0;
  while (flows.size() != total_flows) {
    auto flow = generate_flow(i, config.pkt_size);
    flows.push_back(flow);
    i++;
  }
}

void flows_display() {
  for (const auto& flow : flows) {
    LOG(((flow.src_ip >> 0) & 0xff)
        << "." << ((flow.src_ip >> 8) & 0xff) << "."
        << ((flow.src_ip >> 16) & 0xff) << "." << ((flow.src_ip >> 24) & 0xff)
        << ":" << rte_bswap16(flow.src_port) << " -> "
        << ((flow.dst_ip >> 0) & 0xff) << "." << ((flow.dst_ip >> 8) & 0xff)
        << "." << ((flow.dst_ip >> 16) & 0xff) << "."
        << ((flow.dst_ip >> 24) & 0xff) << ":" << rte_bswap16(flow.dst_port));
  }
}

void free_flows() {
  for (auto flow : flows) {
    free(flow.pkt_buf);
  }
}
