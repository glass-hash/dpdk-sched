#include <cmdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <rte_atomic.h>
#include <rte_ethdev.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "clock.h"
#include "log.h"
#include "pktgen.h"

#define CMDLINE_PARSE_INT_NTOKENS(NTOKENS)            \
  struct {                                            \
    void (*f)(void *, struct cmdline *, void *);      \
    void *data;                                       \
    const char *help_str;                             \
    cmdline_parse_token_hdr_t *tokens[(NTOKENS) + 1]; \
  }

struct cmd_get_params {
  cmdline_fixed_string_t cmd;
};
struct cmd_int_params {
  cmdline_fixed_string_t cmd;
  uint32_t param;
};
struct cmd_intint_params {
  cmdline_fixed_string_t cmd;
  uint32_t param1;
  uint32_t param2;
};

#define INIT_PARAMETERLESS_COMMAND(var, cmd, str) \
  cmdline_parse_token_string_t(var) =             \
      TOKEN_STRING_INITIALIZER(struct cmd_get_params, cmd, (str));

#define INIT_INT_COMMAND(var, cmd, str) \
  cmdline_parse_token_string_t(var) =   \
      TOKEN_STRING_INITIALIZER(struct cmd_int_params, cmd, (str));

/* Parameter-less commands */
INIT_PARAMETERLESS_COMMAND(cmd_quit_token_cmd, cmd, "quit");
INIT_PARAMETERLESS_COMMAND(cmd_start_token_cmd, cmd, "start");
INIT_PARAMETERLESS_COMMAND(cmd_stop_token_cmd, cmd, "stop");
INIT_PARAMETERLESS_COMMAND(cmd_stats_token_cmd, cmd, "stats");
INIT_PARAMETERLESS_COMMAND(cmd_stats_reset_token_cmd, cmd, "reset");
INIT_PARAMETERLESS_COMMAND(cmd_flows_token_cmd, cmd, "flows");

/* Commands taking just an int */
INIT_INT_COMMAND(cmd_rate_token_cmd, cmd, "rate")
INIT_INT_COMMAND(cmd_churn_token_cmd, cmd, "churn")
INIT_INT_COMMAND(cmd_run_token_cmd, cmd, "run")
INIT_INT_COMMAND(cmd_warmup_token_cmd, cmd, "warmup")

cmdline_parse_token_num_t cmd_int_token_param =
    TOKEN_NUM_INITIALIZER(struct cmd_int_params, param, RTE_UINT32);

static inline void signal_new_config() {
  rte_smp_mb();
  rte_atomic64_inc((rte_atomic64_t *)&config.runtime.update_cnt);
}

void cmd_start() {
  config.runtime.running = true;
  signal_new_config();
}

void cmd_stop() {
  config.runtime.running = false;
  signal_new_config();
}

void cmd_rate(rate_gbps_t rate) {
  config.rate = rate;
  config.runtime.rate_per_core = config.rate / config.tx.num_cores;
  signal_new_config();
}

void cmd_churn(churn_fpm_t churn) {
  if (churn > config.max_churn) {
    WARNING("Invalid churn value (requested %" PRIu64
            " is bigger then max %" PRIu64 " fpm). Ignoring request.",
            churn, config.max_churn);
    return;
  }

  uint32_t num_base_flows = config.num_flows / 2;

  if (churn == 0) {
    config.runtime.flow_ttl = 0;
    signal_new_config();
    return;
  }

  double churn_fps = (double)churn / 60;
  assert(churn_fps != 0);

  time_ns_t flow_ttl = (1e9 * (uint64_t)num_base_flows) / churn_fps;

  if (flow_ttl < config.exp_time) {
    WARNING("WARNING: Flow TTL (%" PRIu64
            "ns) is smaller than the expiration time (%" PRIu64
            "ns). Ignoring request.",
            flow_ttl, config.exp_time);
    return;
  }

  LOG_DEBUG("Flow TTL = %" PRIu64 "ns", flow_ttl);

  config.runtime.flow_ttl = flow_ttl;
  signal_new_config();
}

void cmd_activate_warmup() {
  config.warmup_active = true;
  signal_new_config();
}

void cmd_deactivate_warmup() {
  config.warmup_active = false;
  signal_new_config();
}

void cmd_run(time_s_t duration) {
  signal_new_config();

  rate_gbps_t rate = config.rate;

  cmd_rate(config.warmup_rate);
  cmd_activate_warmup();

  cmd_start();
  sleep_s(config.warmup_duration);

  cmd_deactivate_warmup();

  cmd_rate(rate);
  cmd_stats_reset();

  sleep_s(duration);

  cmd_stop();
}

void cmd_warmup(time_s_t time) {
  signal_new_config();

  config.warmup_duration = time;
}

static void cmd_quit_callback(__rte_unused void *ptr_params,
                              struct cmdline *ctx,
                              __rte_unused void *ptr_data) {
  cmdline_quit(ctx);
}

static void cmd_start_callback(__rte_unused void *ptr_params,
                               __rte_unused struct cmdline *ctx,
                               __rte_unused void *ptr_data) {
  cmd_start();
}

static void cmd_stop_callback(__rte_unused void *ptr_params,
                              __rte_unused struct cmdline *ctx,
                              __rte_unused void *ptr_data) {
  cmd_stop();
}

static void cmd_stats_callback(__rte_unused void *ptr_params,
                               __rte_unused struct cmdline *ctx,
                               __rte_unused void *ptr_data) {
  cmd_stats_display_compact();
}

static void cmd_flows_callback(__rte_unused void *ptr_params,
                               __rte_unused struct cmdline *ctx,
                               __rte_unused void *ptr_data) {
  cmd_flows_display();
}

static void cmd_stats_reset_callback(__rte_unused void *ptr_params,
                                     __rte_unused struct cmdline *ctx,
                                     __rte_unused void *ptr_data) {
  cmd_stats_reset();
}

static void cmd_rate_callback(__rte_unused void *ptr_params,
                              __rte_unused struct cmdline *ctx,
                              __rte_unused void *ptr_data) {
  struct cmd_int_params *params = ptr_params;
  rate_gbps_t rate = (double)params->param / 1000.0;
  cmd_rate(rate);
}

static void cmd_churn_callback(__rte_unused void *ptr_params,
                               __rte_unused struct cmdline *ctx,
                               __rte_unused void *ptr_data) {
  struct cmd_int_params *params = ptr_params;
  churn_fpm_t churn = (double)params->param;
  cmd_churn(churn);
}

static void cmd_run_callback(__rte_unused void *ptr_params,
                             __rte_unused struct cmdline *ctx,
                             __rte_unused void *ptr_data) {
  struct cmd_int_params *params = ptr_params;
  time_s_t time = (double)params->param;
  cmd_run(time);
}

static void cmd_warmup_callback(__rte_unused void *ptr_params,
                                __rte_unused struct cmdline *ctx,
                                __rte_unused void *ptr_data) {
  struct cmd_int_params *params = ptr_params;
  time_s_t time = (double)params->param;
  cmd_warmup(time);
}

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_quit_cmd = {
    .f = cmd_quit_callback,
    .data = NULL,
    .help_str = "quit\n     Exit program",
    .tokens = {(void *)&cmd_quit_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_start_cmd = {
    .f = cmd_start_callback,
    .data = NULL,
    .help_str = "start\n     Start packet generation",
    .tokens = {(void *)&cmd_start_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_stop_cmd = {
    .f = cmd_stop_callback,
    .data = NULL,
    .help_str = "stop\n     Stop packet generation",
    .tokens = {(void *)&cmd_stop_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_stats_cmd = {
    .f = cmd_stats_callback,
    .data = NULL,
    .help_str = "stats\n     Show stats",
    .tokens = {(void *)&cmd_stats_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_flows_cmd = {
    .f = cmd_flows_callback,
    .data = NULL,
    .help_str = "flows\n     Show flows",
    .tokens = {(void *)&cmd_flows_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_stats_reset_cmd = {
    .f = cmd_stats_reset_callback,
    .data = NULL,
    .help_str = "reset\n     Reset stats",
    .tokens = {(void *)&cmd_stats_reset_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(2)
cmd_rate_cmd = {
    .f = cmd_rate_callback,
    .data = NULL,
    .help_str = "rate <rate>\n     Set rate in Mbps",
    .tokens = {(void *)&cmd_rate_token_cmd, (void *)&cmd_int_token_param, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(2)
cmd_churn_cmd = {
    .f = cmd_churn_callback,
    .data = NULL,
    .help_str = "churn <churn>\n     Set churn in fpm",
    .tokens = {(void *)&cmd_churn_token_cmd, (void *)&cmd_int_token_param,
               NULL},
};

CMDLINE_PARSE_INT_NTOKENS(2)
cmd_run_cmd = {
    .f = cmd_run_callback,
    .data = NULL,
    .help_str = "run <time>\n     Run for <time> seconds and then stop",
    .tokens = {(void *)&cmd_run_token_cmd, (void *)&cmd_int_token_param, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(2)
cmd_warmup_cmd = {
    .f = cmd_warmup_callback,
    .data = NULL,
    .help_str = "warmup <time>\n     Set warmup duration to <time> seconds",
    .tokens = {(void *)&cmd_warmup_token_cmd, (void *)&cmd_int_token_param,
               NULL},
};

cmdline_parse_ctx_t list_prompt_commands[] = {
    (cmdline_parse_inst_t *)&cmd_quit_cmd,
    (cmdline_parse_inst_t *)&cmd_start_cmd,
    (cmdline_parse_inst_t *)&cmd_stop_cmd,
    (cmdline_parse_inst_t *)&cmd_stats_cmd,
    (cmdline_parse_inst_t *)&cmd_stats_reset_cmd,
    (cmdline_parse_inst_t *)&cmd_flows_cmd,
    (cmdline_parse_inst_t *)&cmd_rate_cmd,
    (cmdline_parse_inst_t *)&cmd_churn_cmd,
    (cmdline_parse_inst_t *)&cmd_run_cmd,
    (cmdline_parse_inst_t *)&cmd_warmup_cmd,
    NULL,
};

void cmdline_start() {
  struct cmdline *ctx_cmdline;

  signal_new_config();

  ctx_cmdline = cmdline_stdin_new(list_prompt_commands, "Pktgen> ");
  cmdline_interact(ctx_cmdline);
  cmdline_stdin_exit(ctx_cmdline);
}
