#ifndef PKTGEN_SRC_FLOWS_H_
#define PKTGEN_SRC_FLOWS_H_

#include <vector>

#include "pktgen.h"

extern std::vector<flow_t> flows;

void generate_flows();
void free_flows();
void flows_display();

#endif
