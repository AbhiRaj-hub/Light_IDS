#ifndef IDS_PACKET_PROCESSOR_H
#define IDS_PACKET_PROCESSOR_H

#include "alert_sender.h"
#include "anomaly_detector.h"
#include "event_logger.h"
#include "packet_types.h"
#include "signature_detector.h"
#include <pcap/pcap.h>
#include <signal.h>

// Packet Processor Data Structure
typedef struct {
  signature_detector_t *sigdet;
  anomaly_detector_t *anomdet;
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

// Lifecycle
void pp_init(packet_processor_t *pp, signature_detector_t *sigdet,
             anomaly_detector_t *anomdet, alert_sender_t *alertsender,
             event_logger_t *logger, const char *interface,
             const char *bpf_filter, int ignore_local); // Initialization

int pp_start_live_capture(
    packet_processor_t
        *pp); // Opens Network Interface for real time packet analysis
int pp_process_pcap_file(packet_processor_t *pp,
                         const char *pcap_path); // Reads from pcap files
void pp_stop(packet_processor_t *pp);
void pp_get_stats(packet_processor_t *pp, unsigned long *packets,
                  double *elapsed,
                  double *pps); // Returns Total Packets Proccesed and PPS

#endif
