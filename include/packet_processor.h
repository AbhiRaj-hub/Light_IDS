#ifndef IDS_PACKET_PROCESSOR_H
#define IDS_PACKET_PROCESSOR_H

#include "alert_sender.h"
#include "anomaly_detector.h"
#include "event_logger.h"
#include "packet_types.h"
#include "signature_detector.h"
#include <csignal>
#include <pcap/pcap.h>
#include <signal.h>

typedef struct {
  signature_detector_t *sigdet;
  anomaly_detector_t *anomdet;:
  alert_sender_t *alertsender;
  event_logger_t *logger;
  char interface[64];
  char bpf_filter[256];
  int ignore_local;
  pcap_t *pcap_handle;
  unsigned long packet_count;
  double start_time;
  volatile sig_atomic_t stop_flag;
} packet_processor_t;

#endif
