#include <getopt.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "pktgen.h"

#define CMD_OPT_HELP "help"
#define CMD_OPT_TEST "test"
#define CMD_OPT_TOTAL_FLOWS "total-flows"
#define CMD_OPT_PKT_SIZE "pkt-size"
#define CMD_OPT_TX_PORT "tx"
#define CMD_OPT_RX_PORT "rx"
#define CMD_OPT_NUM_TX_CORES "tx-cores"
#define CMD_OPT_EXP_TIME "exp-time"
#define CMD_OPT_CRC_UNIQUE_FLOWS "crc-unique-flows"
#define CMD_OPT_CRC_BITS "crc-bits"

#define DEFAULT_PKT_SIZE MIN_PKT_SIZE
#define DEFAULT_CRC_UNIQUE_FLOWS false
#define DEFAULT_TOTAL_FLOWS 10000
#define DEFAULT_CRC_BITS 32

#define DEFAULT_WARMUP_DURATION 0  // No warmup
#define DEFAULT_WARMUP_RATE 1      // 1 Mbps

enum {
  /* long options mapped to short options: first long only option value must
   * be >= 256, so that it does not conflict with short options.
   */
  CMD_OPT_HELP_NUM = 256,
  CMD_OPT_TEST_NUM,
  CMD_OPT_TOTAL_FLOWS_NUM,
  CMD_OPT_PKT_SIZE_NUM,
  CMD_OPT_TX_PORT_NUM,
  CMD_OPT_RX_PORT_NUM,
  CMD_OPT_NUM_TX_CORES_NUM,
  CMD_OPT_EXP_TIME_NUM,
  CMD_OPT_CRC_UNIQUE_FLOWS_NUM,
  CMD_OPT_CRC_BITS_NUM,
};

/* if we ever need short options, add to this string */
static const char short_options[] = "";

static const struct option long_options[] = {
    {CMD_OPT_HELP, no_argument, NULL, CMD_OPT_HELP_NUM},
    {CMD_OPT_TEST, no_argument, NULL, CMD_OPT_TEST_NUM},
    {CMD_OPT_TOTAL_FLOWS, required_argument, NULL, CMD_OPT_TOTAL_FLOWS_NUM},
    {CMD_OPT_PKT_SIZE, required_argument, NULL, CMD_OPT_PKT_SIZE_NUM},
    {CMD_OPT_TX_PORT, required_argument, NULL, CMD_OPT_TX_PORT_NUM},
    {CMD_OPT_RX_PORT, required_argument, NULL, CMD_OPT_RX_PORT_NUM},
    {CMD_OPT_NUM_TX_CORES, required_argument, NULL, CMD_OPT_NUM_TX_CORES_NUM},
    {CMD_OPT_EXP_TIME, required_argument, NULL, CMD_OPT_EXP_TIME_NUM},
    {CMD_OPT_CRC_UNIQUE_FLOWS, no_argument, NULL, CMD_OPT_CRC_UNIQUE_FLOWS_NUM},
    {CMD_OPT_CRC_BITS, required_argument, NULL, CMD_OPT_CRC_BITS_NUM},
    {NULL, 0, NULL, 0}};

void config_print_usage(char **argv) {
  LOG("Usage:\n"
      "%s [EAL options] --\n"
      "\t[--help]: Show this help and exit\n"
      "\t[--test]: Run test and exit\n"
      "\t[--" CMD_OPT_TOTAL_FLOWS
      "] <#flows>: Total number of flows (default=%" PRIu32
      ")\n"
      "\t[--" CMD_OPT_PKT_SIZE "] <size>: Packet size (bytes) (default=%" PRIu64
      "B)\n"
      "\t--" CMD_OPT_TX_PORT
      " <port>: TX port\n"
      "\t--" CMD_OPT_RX_PORT
      " <port>: RX port\n"
      "\t--" CMD_OPT_NUM_TX_CORES
      " <#cores>: Number of TX cores\n"
      "\t--" CMD_OPT_EXP_TIME
      " <time>: Flow expiration time (in us)\n"
      "\t[--" CMD_OPT_CRC_UNIQUE_FLOWS
      "]: Flows are CRC unique (default=%s)\n"
      "\t[--" CMD_OPT_CRC_BITS " <bits>]: CRC bits (default=%" PRIu32 ")",
      argv[0], DEFAULT_TOTAL_FLOWS, DEFAULT_PKT_SIZE,
      DEFAULT_CRC_UNIQUE_FLOWS ? "true" : "false", DEFAULT_CRC_BITS);
}

static uintmax_t parse_int(const char *str, const char *name, int base) {
  char *temp;
  intmax_t result = strtoimax(str, &temp, base);

  // There's also a weird failure case with overflows, but let's not care
  if (temp == str || *temp != '\0') {
    rte_exit(EXIT_FAILURE, "Error while parsing '%s': %s\n", name, str);
  }

  return result;
}

#define PARSER_ASSERT(cond, fmt, ...) \
  if (!(cond)) rte_exit(EXIT_FAILURE, fmt, ##__VA_ARGS__);

void config_init(int argc, char **argv) {
  // Default configuration values
  config.test_and_exit = false;
  config.num_flows = DEFAULT_TOTAL_FLOWS;
  config.crc_unique_flows = DEFAULT_CRC_UNIQUE_FLOWS;
  config.crc_bits = DEFAULT_CRC_BITS;
  config.exp_time = 0;
  config.pkt_size = DEFAULT_PKT_SIZE;
  config.warmup_duration = DEFAULT_WARMUP_DURATION;
  config.warmup_rate = DEFAULT_WARMUP_RATE;
  config.rx.port = 0;
  config.tx.port = 1;
  config.tx.num_cores = 1;

  // Setup runtime configuration
  config.runtime.running = false;
  config.runtime.update_cnt = 0;
  config.runtime.rate_per_core = 0;
  config.runtime.flow_ttl = 0;

  unsigned nb_devices = rte_eth_dev_count_avail();
  unsigned nb_cores = rte_lcore_count();

  if (nb_devices < 2) {
    rte_exit(EXIT_FAILURE,
             "Insufficient number of available devices (%" PRIu16
             " detected, but we require at least 2).\n",
             nb_devices);
  }

  if (nb_cores < 2) {
    rte_exit(EXIT_FAILURE,
             "Insufficient number of cores (%" PRIu16
             " given, but we require at least 2).\n",
             nb_cores);
  }

  if (argc <= 1) {
    config_print_usage(argv);
    exit(0);
  }

  int opt;
  while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) !=
         EOF) {
    switch (opt) {
      case CMD_OPT_HELP_NUM: {
        config_print_usage(argv);
        exit(0);
      } break;
      case CMD_OPT_TEST_NUM: {
        config.test_and_exit = true;
      } break;
      case CMD_OPT_TOTAL_FLOWS_NUM: {
        config.num_flows = parse_int(optarg, CMD_OPT_TOTAL_FLOWS, 10);

        PARSER_ASSERT(config.num_flows >= MIN_FLOWS_NUM,
                      "Number of flows must be >= %" PRIu32
                      " (requested %" PRIu16 ").\n",
                      MIN_FLOWS_NUM, config.num_flows);

        PARSER_ASSERT(config.num_flows % 2 == 0,
                      "Number of flows must be even (requested %" PRIu16 ").\n",
                      config.num_flows);
      } break;
      case CMD_OPT_CRC_UNIQUE_FLOWS_NUM: {
        config.crc_unique_flows = true;
      } break;
      case CMD_OPT_CRC_BITS_NUM: {
        config.crc_bits = parse_int(optarg, CMD_OPT_TOTAL_FLOWS, 10);
        PARSER_ASSERT(
            config.crc_bits >= MIN_CRC_BITS && config.crc_bits <= MAX_CRC_BITS,
            "CRC bits must be in the interval [%" PRIu32 "-%" PRIu32
            "] (requested %" PRIu32 ").\n",
            MIN_CRC_BITS, MAX_CRC_BITS, config.crc_bits);
      } break;
      case CMD_OPT_EXP_TIME_NUM: {
        time_us_t exp_time = parse_int(optarg, CMD_OPT_EXP_TIME, 10);
        config.exp_time = 1000 * exp_time;
      } break;
      case CMD_OPT_PKT_SIZE_NUM: {
        config.pkt_size = parse_int(optarg, CMD_OPT_PKT_SIZE, 10);
        PARSER_ASSERT(
            config.pkt_size >= MIN_PKT_SIZE && config.pkt_size <= MAX_PKT_SIZE,
            "Packet size must be in the interval [%" PRIu64 "-%" PRIu64
            "] (requested %" PRIu64 ").\n",
            MIN_PKT_SIZE, MAX_PKT_SIZE, config.pkt_size);
      } break;
      case CMD_OPT_TX_PORT_NUM: {
        config.tx.port = parse_int(optarg, CMD_OPT_TX_PORT, 10);
        PARSER_ASSERT(config.tx.port < nb_devices,
                      "Invalid TX device: requested %" PRIu16
                      " but only %" PRIu16 " available.\n",
                      config.tx.port, nb_devices);
      } break;
      case CMD_OPT_RX_PORT_NUM: {
        config.rx.port = parse_int(optarg, CMD_OPT_RX_PORT, 10);
        PARSER_ASSERT(config.rx.port < nb_devices,
                      "Invalid RX device: requested %" PRIu16
                      " but only %" PRIu16 " available.\n",
                      config.rx.port, nb_devices);
      } break;
      case CMD_OPT_NUM_TX_CORES_NUM: {
        config.tx.num_cores = parse_int(optarg, CMD_OPT_NUM_TX_CORES, 10);
        PARSER_ASSERT(config.tx.num_cores > 0,
                      "Number of TX cores must be positive (requested %" PRIu16
                      ").\n",
                      config.tx.num_cores);
      } break;
      default:
        rte_exit(EXIT_FAILURE, "Unknown option %c\n", opt);
    }
  }

  PARSER_ASSERT(
      !config.crc_unique_flows || (config.num_flows <= (1 << config.crc_bits)),
      "Not enough CRC bits for the requested number of flows (flows=%" PRIu16
      ", crc bits=%" PRIu16 ", max flows=%" PRIu16 ").\n",
      config.num_flows, config.crc_bits, 1 << config.crc_bits);

  PARSER_ASSERT(config.tx.num_cores < nb_cores,
                "Insufficient number of cores (main=1, tx=%" PRIu16
                ", available=%" PRIu16 ").\n",
                config.tx.num_cores, nb_cores);

  PARSER_ASSERT((config.num_flows / 2) >= config.tx.num_cores,
                "Too many cores (%" PRIu16
                ") for the requested number of flows (%" PRIu16
                "). Use at most half the number of flows.\n",
                config.tx.num_cores, config.num_flows);

  config.max_churn = ((double)(60.0 * config.num_flows)) /
                     NS_TO_S(MIN_CHURN_ACTION_TIME_MULTIPLER * config.exp_time);

  unsigned idx = 0;
  unsigned lcore_id;
  RTE_LCORE_FOREACH_WORKER(lcore_id) { config.tx.cores[idx++] = lcore_id; }

  // Reset getopt
  optind = 1;
}

void config_print() {
  LOG("\n----- Config -----");
  LOG("RX port:          %" PRIu16, config.rx.port);
  LOG("TX port:          %" PRIu16, config.tx.port);
  LOG("TX cores:         %" PRIu16, config.tx.num_cores);
  LOG("Flows:            %" PRIu16 "", config.num_flows);
  LOG("Flows CRC unique: %s", config.crc_unique_flows ? "true" : "false");
  LOG("CRC bits:         %" PRIx32 "", config.crc_bits);
  LOG("Expiration time:  %" PRIu64 " us", config.exp_time / 1000);
  LOG("Packet size       %" PRIu64 " bytes", config.pkt_size);
  LOG("Max churn:        %" PRIu64 " fpm", config.max_churn);
  LOG("------------------\n");
}
