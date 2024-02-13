#include <rte_common.h>
#include <rte_ethdev.h>

#include "pktgen.h"

static void cmd_stats_display_port(uint16_t port_id) {
  struct rte_eth_stats stats;

  constexpr uint16_t max_num_stats = 1024;

  rte_eth_stats_get(port_id, &stats);

  printf("==== Statistics ====\n");
  printf("Port %" PRIu8 "\n", port_id);
  printf("    ipackets: %" PRIu64 "\n", stats.ipackets);
  printf("    opackets: %" PRIu64 "\n", stats.opackets);
  printf("    ibytes: %" PRIu64 "\n", stats.ibytes);
  printf("    obytes: %" PRIu64 "\n", stats.obytes);
  printf("    imissed: %" PRIu64 "\n", stats.imissed);
  printf("    oerrors: %" PRIu64 "\n", stats.oerrors);
  printf("    rx_nombuf: %" PRIu64 "\n", stats.rx_nombuf);
  printf("\n");

  printf("==== Extended Statistics ====\n");
  int num_xstats = rte_eth_xstats_get(port_id, NULL, 0);
  struct rte_eth_xstat xstats[max_num_stats];
  if (rte_eth_xstats_get(port_id, xstats, num_xstats) != num_xstats) {
    fprintf(stderr, "Cannot get xstats (port %u)\n", port_id);
    return;
  }
  struct rte_eth_xstat_name xstats_names[max_num_stats];
  if (rte_eth_xstats_get_names(port_id, xstats_names, num_xstats) !=
      num_xstats) {
    fprintf(stderr, "Cannot get xstats (port %u)\n", port_id);
    return;
  }
  for (int i = 0; i < num_xstats; ++i) {
    printf("%s: %" PRIu64 "\n", xstats_names[i].name, xstats[i].value);
  }
  printf("\n");
}

static uint64_t get_port_xstat(uint16_t port, const char* name) {
  uint64_t xstat_id = 0;
  uint64_t xstat_value = 0;

  if (rte_eth_xstats_get_id_by_name(port, name, &xstat_id) != 0) {
    fprintf(stderr, "Error retrieving %s xstat ID (port %u)\n", name, port);
    return xstat_value;
  }

  if (rte_eth_xstats_get_by_id(port, &xstat_id, &xstat_value, 1) < 0) {
    fprintf(stderr, "Error retrieving %s xstat (port %u)\n", name, port);
    return xstat_value;
  }

  return xstat_value;
}

stats_t get_stats() {
  uint64_t rx_good_pkts = get_port_xstat(config.rx.port, "rx_good_packets");
  uint64_t rx_missed_pkts = get_port_xstat(config.rx.port, "rx_missed_errors");

  // We don't care if we missed them, the fact that we've received them back is
  // good enough.
  uint64_t rx_pkts = rx_good_pkts + rx_missed_pkts;
  uint64_t tx_pkts = get_port_xstat(config.tx.port, "tx_good_packets");

  // Reseting stats is not atomic, so there's a chance we detect more packets
  // received that sent. It's not that problematic, but let's take that into
  // consideration.
  rx_pkts = RTE_MIN(rx_pkts, tx_pkts);

  stats_t stats = {.rx_pkts = rx_pkts, .tx_pkts = tx_pkts};

  return stats;
}

void cmd_stats_display() {
  printf("~~~~ TX port %u ~~~~\n", config.tx.port);
  cmd_stats_display_port(config.tx.port);

  printf("\n");
  printf("~~~~ RX port %u ~~~~\n", config.rx.port);
  cmd_stats_display_port(config.rx.port);

  cmd_stats_display_compact();
}

void cmd_stats_display_compact() {
  stats_t stats = get_stats();

  float loss = (float)(stats.tx_pkts - stats.rx_pkts) / stats.tx_pkts;

  printf("\n");
  printf("~~~~~~ Pktgen ~~~~~~\n");
  printf("  TX:   %" PRIu64 "\n", stats.tx_pkts);
  printf("  RX:   %" PRIu64 "\n", stats.rx_pkts);
  printf("  Loss: %.2f%%\n", 100 * loss);
}

static void reset_stats(uint16_t port) {
  int retval = 0;

  retval = rte_eth_stats_reset(port);
  if (retval != 0) {
    fprintf(stderr, "Error reseting stats (port %u) info: %s\n", port,
            strerror(-retval));
  }

  retval = rte_eth_xstats_reset(port);
  if (retval != 0) {
    fprintf(stderr, "Error reseting xstats (port %u) info: %s\n", port,
            strerror(-retval));
  }
}

void cmd_stats_reset() {
  reset_stats(config.tx.port);
  reset_stats(config.rx.port);
}