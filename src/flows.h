#ifndef PKTGEN_SRC_FLOWS_H_
#define PKTGEN_SRC_FLOWS_H_

#include <vector>

#include "pktgen.h"

void generate_unique_flows_per_worker();
const std::vector<flow_t>& get_worker_flows(unsigned worker_id);

#endif