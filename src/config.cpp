#include <getopt.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "pktgen.h"

#define CMD_HELP "help"
#define CMD_FLOWS_PER_CORE "flows-per-core"
#define CMD_PKT_SIZE "pkt-size"
#define CMD_TX_PORT "tx"
#define CMD_NUM_CORES "num-cores"
#define CMD_TIMEOUT "timeout"

#define DEFAULT_PKT_SIZE MIN_PKT_SIZE
#define DEFAULT_FLOWS_PER_CORE 10000

enum {
  /* long options mapped to short options: first long only option value must
   * be >= 256, so that it does not conflict with short options.
   */
  CMD_HELP_NUM = 256,
  CMD_FLOWS_PER_CORE_NUM,
  CMD_PKT_SIZE_NUM,
  CMD_TX_PORT_NUM,
  CMD_NUM_CORES_NUM,
  CMD_TIMEOUT_NUM,
};

/* if we ever need short options, add to this string */
static const char short_options[] = "";

static const struct option long_options[] = {
    {CMD_HELP, no_argument, NULL, CMD_HELP_NUM},
    {CMD_FLOWS_PER_CORE, required_argument, NULL, CMD_FLOWS_PER_CORE_NUM},
    {CMD_PKT_SIZE, required_argument, NULL, CMD_PKT_SIZE_NUM},
    {CMD_TX_PORT, required_argument, NULL, CMD_TX_PORT_NUM},
    {CMD_NUM_CORES, required_argument, NULL, CMD_NUM_CORES_NUM},
    {CMD_TIMEOUT, optional_argument, NULL, CMD_TIMEOUT_NUM},
    {NULL, 0, NULL, 0}};

void config_print_usage(char **argv) {
  LOG("Usage:\n"
      "%s [EAL options] --\n"
      "\t[--help]: Show this help and exit\n"
      "\t[--" CMD_FLOWS_PER_CORE
      "] <#flows>: Total number of flows (default=%" PRIu32
      ")\n"
      "\t[--" CMD_PKT_SIZE "] <size>: Packet size (bytes) (default=%" PRIu64
      "B)\n"
      "\t--" CMD_TX_PORT
      " <port>: TX port\n"
      "\t--" CMD_NUM_CORES
      " <#cores>: Number of TX cores\n"
      "\t[--timeout] <timeout value>: Test duration (seconds)\n",
      argv[0], DEFAULT_FLOWS_PER_CORE, DEFAULT_PKT_SIZE);
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
  config.flows_per_core = 0;
  config.pkt_size = DEFAULT_PKT_SIZE;
  config.timeout = 0;
  config.port = 1;
  config.num_cores = 1;

  unsigned nb_devices = rte_eth_dev_count_avail();
  unsigned nb_cores = rte_lcore_count();

  if (nb_devices < 1) {
    rte_exit(EXIT_FAILURE,
             "Insufficient number of available devices (%" PRIu16
             " detected, but we require at least 2).\n",
             nb_devices);
  }

  if (nb_cores < 1) {
    rte_exit(EXIT_FAILURE,
             "Insufficient number of cores (%" PRIu16
             " given, but we require at least 1).\n",
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
      case CMD_HELP_NUM: {
        config_print_usage(argv);
        exit(0);
      } break;
      case CMD_FLOWS_PER_CORE_NUM: {
        config.flows_per_core = parse_int(optarg, CMD_FLOWS_PER_CORE, 10);

        PARSER_ASSERT(config.flows_per_core >= MIN_FLOWS_NUM,
                      "Flows per worker must be >= %" PRIu32
                      " (requested %" PRIu32 ").\n",
                      MIN_FLOWS_NUM, config.flows_per_core);

      } break;
      case CMD_PKT_SIZE_NUM: {
        config.pkt_size = parse_int(optarg, CMD_PKT_SIZE, 10);
        PARSER_ASSERT(
            config.pkt_size >= MIN_PKT_SIZE && config.pkt_size <= MAX_PKT_SIZE,
            "Packet size must be in the interval [%" PRIu64 "-%" PRIu64
            "] (requested %" PRIu64 ").\n",
            MIN_PKT_SIZE, MAX_PKT_SIZE, config.pkt_size);
      } break;
      case CMD_TX_PORT_NUM: {
        config.port = parse_int(optarg, CMD_TX_PORT, 10);
        PARSER_ASSERT(config.port <= nb_devices,
                      "Invalid TX device: requested %" PRIu16
                      " but only %" PRIu16 " available.\n",
                      config.port, nb_devices);
      } break;
      case CMD_NUM_CORES_NUM: {
        config.num_cores = parse_int(optarg, CMD_NUM_CORES, 10);
        PARSER_ASSERT(config.num_cores > 0,
                      "Number of TX cores must be positive (requested %" PRIu16
                      ").\n",
                      config.num_cores);
      } break;
      case CMD_TIMEOUT_NUM: {
        if (optarg != NULL) {
            config.timeout = parse_int(optarg, CMD_TIMEOUT, 10);
        }
      } break;
      default:
        rte_exit(EXIT_FAILURE, "Unknown option %c\n", opt);
    }
  }

  PARSER_ASSERT(config.num_cores <= nb_cores,
                "Insufficient number of cores (main=1, tx=%" PRIu16
                ", available=%" PRIu16 ").\n",
                config.num_cores, nb_cores);

  unsigned idx = 0;
  unsigned lcore_id;
  RTE_LCORE_FOREACH_WORKER(lcore_id) { config.cores[idx++] = lcore_id; }

  // Reset getopt
  optind = 1;
}

void config_print() {
  LOG("\n----- Config -----");
  LOG("TX port:          %" PRIu16, config.port);
  LOG("Num of cores:     %" PRIu16, config.num_cores);
  LOG("Flows per core:   %" PRIu16 "", config.flows_per_core);
  LOG("Packet size:      %" PRIu64 " bytes", config.pkt_size);
  LOG("Timeout:          %" PRIu32 " seconds", config.timeout);
  LOG("------------------\n");
}
