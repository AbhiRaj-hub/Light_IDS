#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "alert_sender.h"
#include "anomaly_detector.h"
#include "event_logger.h"
#include "packet_processor.h"
#include "signature_detector.h"


static packet_processor_t *g_pp = NULL;

static void handle_sigint(int signum) {
  (void)signum;
  if (g_pp)
    pp_stop(g_pp); /* pcap_breakloop is documented as signal-handler safe */
}

static void print_usage(const char *prog) {
  printf("\n");
  printf("     __    ___ ____  ____\n");
  printf("    / /   |_ _|  _ \\/ ___|\n");
  printf("   / /     | || | | \\___ \\\n");
  printf("  / /___   | || |_| |___) |\n");
  printf(" /_____/  |___|____/|____/\n");
  printf("\n");
  printf("Lightweight IDS (C) - signature + anomaly based network monitor\n\n");
  printf("Usage:\n");
  printf("  sudo %s -i eth0\n", prog);
  printf("  sudo %s -i eth0 -f \"tcp or udp\"\n", prog);
  printf("  %s --pcap sample.pcap\n\n", prog);
  printf("Options:\n");
  printf("  -i, --interface <name>   Network interface to sniff on\n");
  printf(
      "  -f, --filter <bpf>       BPF capture filter, e.g. \"tcp port 80\"\n");
  printf("      --pcap <path>        Replay a .pcap file instead of live "
         "capture\n");
  printf("      --rules <path>       Path to signature rules JSON (default "
         "config/rules.json)\n");
  printf("      --config <path>      Path to alerting config JSON (default "
         "config/alerting.json)\n");
  printf(
      "      --log-dir <path>     Directory for event logs (default logs)\n");
  printf("  -q, --quiet              Only print high/critical events to "
         "console\n");
  printf("  -h, --help               Show this help\n");
}

int main(int argc, char **argv) {
  const char *interface = NULL;
  const char *filter = NULL;
  const char *pcap_path = NULL;
  const char *rules_path = "config/rules.json";
  const char *config_path = "config/alerting.json";
  const char *log_dir = "logs";
  int quiet = 0;

  static struct option long_opts[] = {{"interface", required_argument, 0, 'i'},
                                      {"filter", required_argument, 0, 'f'},
                                      {"pcap", required_argument, 0, 1000},
                                      {"rules", required_argument, 0, 1001},
                                      {"config", required_argument, 0, 1002},
                                      {"log-dir", required_argument, 0, 1003},
                                      {"quiet", no_argument, 0, 'q'},
                                      {"help", no_argument, 0, 'h'},
                                      {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "i:f:qh", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'i':
      interface = optarg;
      break;
    case 'f':
      filter = optarg;
      break;
    case 1000:
      pcap_path = optarg;
      break;
    case 1001:
      rules_path = optarg;
      break;
    case 1002:
      config_path = optarg;
      break;
    case 1003:
      log_dir = optarg;
      break;
    case 'q':
      quiet = 1;
      break;
    case 'h':
      print_usage(argv[0]);
      return 0;
    default:
      print_usage(argv[0]);
      return 1;
    }
  }

  event_logger_t logger;
  logger_init(&logger, log_dir, "ids_events.jsonl", 1,
              quiet ? SEV_HIGH : SEV_INFO);

  FILE *rf = fopen(rules_path, "r");
  if (!rf) {
    logger_log(&logger, SEV_HIGH, "main", "Rules file not found: %s",
               rules_path);
    logger_destroy(&logger);
    return 1;
  }
  fclose(rf);

  signature_detector_t sigdet;
  if (sigdet_load(&sigdet, rules_path, &logger) != 0) {
    logger_destroy(&logger);
    return 1;
  }

  anomaly_detector_t anomdet;
  anomdet_init(&anomdet, &logger);

  alert_config_t alert_cfg;
  alertsender_load_config(&alert_cfg, config_path, &logger);
  alert_sender_t alertsender;
  alertsender_init(&alertsender, alert_cfg, &logger);

  packet_processor_t pp;
  pp_init(&pp, &sigdet, &anomdet, &alertsender, &logger, interface, filter, 1);
  g_pp = &pp;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_sigint;
  sigaction(SIGINT, &sa, NULL);

  int rc;
  if (pcap_path) {
    rc = pp_process_pcap_file(&pp, pcap_path);
  } else {
    if (geteuid() != 0) {
      logger_log(&logger, SEV_INFO, "main",
                 "Live capture typically requires root privileges for raw "
                 "socket access. "
                 "Re-run with sudo if capture fails to start.");
    }
    rc = pp_start_live_capture(&pp);
  }

  unsigned long packets;
  double elapsed, pps;
  pp_get_stats(&pp, &packets, &elapsed, &pps);
  logger_log(&logger, SEV_INFO, "main",
             "Session stats: packets_processed=%lu elapsed_seconds=%.1f "
             "packets_per_second=%.2f",
             packets, elapsed, pps);

  sigdet_free(&sigdet);
  anomdet_destroy(&anomdet);
  alertsender_destroy(&alertsender);
  logger_destroy(&logger);

  return (rc == 0) ? 0 : 1;
}
