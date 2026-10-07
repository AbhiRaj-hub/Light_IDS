#ifndef IDS_ANOMALY_DETECTOR_H
#define IDS_ANOMALY_DETECTOR_H

#include "event_logger.h"
#include "packet_types.h"
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>

#define AD_HASH_BUCKETS 4096
#define AD_RATE_HISTORY_MAX 120

// Sliding Window
typedef struct {
  double *timestamps;
  int *aux; // Optional Value with Each timestamp
  size_t count;
  size_t capacity;
} ad_time_window_t;

// Host state
typedef struct ad_host_state {
  char ip[INET_ADDRSTRLEN];
  ad_time_window_t port_activity;
  ad_time_window_t syn_activity;
  ad_time_window_t traffic_activity;
  double rate_history[AD_RATE_HISTORY_MAX];
  size_t rate_history_count;
  size_t rate_history_next;
  double last_rate_sample_time;
  struct ad_host_state *next;
} ad_host_state_t;

// Anomaly Detector Object
typedef struct {
  ad_host_state_t *buckets[AD_HASH_BUCKETS];
  pthread_mutex_t lock;
  int port_scan_threshold;
  double port_scan_window;
  int syn_flood_threshold;
  double syn_flood_window;
  double zscore_threshold;
  double traffic_window;
  event_logger_t *logger;
} anomaly_detector_t;

typedef struct {
  char type[32];
  severity_t severity;
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  char detail[256];
} anomaly_finding_t;

void anomdet_init(anomaly_detector_t *det, event_logger_t *logger);
void anomdet_init_custom(anomaly_detector_t *det, event_logger_t *logger,
                         int port_scan_threshold, double port_scan_window,
                         int syn_flood_threshold, double syn_flood_window,
                         double zscore_threshold, double traffic_window);
void anomdet_destroy(anomaly_detector_t *det);

size_t anomdet_analyze(anomaly_detector_t *det, const parsed_packet_t *pkt,
                       anomaly_finding_t *out, size_t max_out);

#endif
