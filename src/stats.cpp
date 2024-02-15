#include <rte_common.h>
#include <rte_ethdev.h>

#include "log.h"
#include "pktgen.h"

static void cmd_stats_display_port(uint16_t port_id) {
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

static uint64_t get_port_xstat(uint16_t port, const char* name) {
  uint64_t xstat_id = 0;
  uint64_t xstat_value = 0;

  if (rte_eth_xstats_get_id_by_name(port, name, &xstat_id) != 0) {
    WARNING("Error retrieving %s xstat ID (port %u)", name, port);
    return xstat_value;
  }

  if (rte_eth_xstats_get_by_id(port, &xstat_id, &xstat_value, 1) < 0) {
    WARNING("Error retrieving %s xstat (port %u)", name, port);
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
  LOG("~~~~ TX port %u ~~~~", config.tx.port);
  cmd_stats_display_port(config.tx.port);

  LOG();
  LOG("~~~~ RX port %u ~~~~", config.rx.port);
  cmd_stats_display_port(config.rx.port);

  cmd_stats_display_compact();
}

void cmd_stats_display_compact() {
  stats_t stats = get_stats();

  float loss = (float)(stats.tx_pkts - stats.rx_pkts) / stats.tx_pkts;

  LOG();
  LOG("~~~~~~ Pktgen ~~~~~~");
  LOG("  TX:   %" PRIu64, stats.tx_pkts);
  LOG("  RX:   %" PRIu64, stats.rx_pkts);
  LOG("  Loss: %.2f%%", 100 * loss);
}

static void reset_stats(uint16_t port) {
  int retval = 0;

  retval = rte_eth_stats_reset(port);
  if (retval != 0) {
    WARNING("Error reseting stats (port %u) info: %s", port, strerror(-retval));
  }

  retval = rte_eth_xstats_reset(port);
  if (retval != 0) {
    WARNING("Error reseting xstats (port %u) info: %s", port,
            strerror(-retval));
  }
}

void cmd_stats_reset() {
  reset_stats(config.tx.port);
  reset_stats(config.rx.port);
}