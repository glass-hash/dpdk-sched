#include <rte_common.h>
#include <rte_random.h>

#include <unordered_set>
#include <vector>

#include "log.h"
#include "pktgen.h"

std::vector<std::vector<flow_t>> flows_per_worker;

static flow_t generate_sequential_flow(uint32_t index) {
    rte_be32_t src_ip = rte_cpu_to_be_32(0x0A000001);  // 10.0.0.1

    uint32_t base_ip = 0xC0A80000;  // 192.168.0.0
    rte_be32_t dst_ip = rte_cpu_to_be_32(base_ip + index);

    rte_be16_t src_port = rte_cpu_to_be_16(8080);
    rte_be16_t dst_port = rte_cpu_to_be_16(80);

    return {src_ip, dst_ip, src_port, dst_port};
}

struct flow_hash_t {
  size_t operator()(const flow_t& flow) const {
    size_t hash = std::hash<int>()(flow.src_ip);
    hash ^= std::hash<int>()(flow.dst_ip);
    hash ^= std::hash<int>()(flow.src_port);
    hash ^= std::hash<int>()(flow.dst_port);
    return hash;
  }
};

struct flow_comp_t {
  bool operator()(const flow_t& f1, const flow_t& f2) const {
    return f1.src_ip == f2.src_ip && f1.dst_ip == f2.dst_ip &&
           f1.src_port == f2.src_port && f1.dst_port == f2.dst_port;
  };
};

void generate_unique_flows_per_worker() {
  flows_per_worker = std::vector<std::vector<flow_t>>(config.tx.num_cores);

  std::unordered_set<flow_t, flow_hash_t, flow_comp_t> flows_set;
  int worker_idx = 0;

  LOG("Generating %d flows...", config.num_flows);

  uint32_t i = 0;
  while (flows_set.size() != config.num_flows) {
    auto flow = generate_sequential_flow(i);

    // Already generated. Unlikely, but we still check...
    if (flows_set.find(flow) != flows_set.end()) {
      continue;
    }

    flows_set.insert(flow);
    flows_per_worker[worker_idx].push_back(flow);

    // Every worker should only see an even number of flows.
    if (flows_set.size() % 2 == 0) {
      worker_idx = (worker_idx + 1) % config.tx.num_cores;
    }
    i++;
  }
}

const std::vector<flow_t>& get_worker_flows(unsigned worker_id) {
  return flows_per_worker[worker_id];
}

void cmd_flows_display() {
  LOG();
  LOG("~~~~~~ %u flows ~~~~~~", config.num_flows);
  for (const auto& flows : flows_per_worker) {
    for (const auto& flow : flows) {
      LOG("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u", (flow.src_ip >> 0) & 0xff,
          (flow.src_ip >> 8) & 0xff, (flow.src_ip >> 16) & 0xff,
          (flow.src_ip >> 24) & 0xff, rte_bswap16(flow.src_port),
          (flow.dst_ip >> 0) & 0xff, (flow.dst_ip >> 8) & 0xff,
          (flow.dst_ip >> 16) & 0xff, (flow.dst_ip >> 24) & 0xff,
          rte_bswap16(flow.dst_port));
    }
  }
}
