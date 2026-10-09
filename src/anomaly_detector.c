#define _GNU_SOURCE
#include "anomaly_detector.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


static double now_seconds(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static unsigned long hash_str(const char *s) {
  unsigned long h = 5381;
  int c;
  while ((c = (unsigned char)*s++))
    h = ((h << 5) + h) + (unsigned long)c;
  return h;
}

static void tw_push(ad_time_window_t *tw, double ts, int aux) {
  if (tw->count >= tw->capacity) {
    size_t newcap = tw->capacity ? tw->capacity * 2 : 16;
    tw->timestamps = realloc(tw->timestamps, newcap * sizeof(double));
    tw->aux = realloc(tw->aux, newcap * sizeof(int));
    tw->capacity = newcap;
  }
  tw->timestamps[tw->count] = ts;
  tw->aux[tw->count] = aux;
  tw->count++;
}

static void tw_trim(ad_time_window_t *tw, double now, double window_seconds) {
  size_t drop = 0;
  while (drop < tw->count && (now - tw->timestamps[drop]) > window_seconds)
    drop++;
  if (drop == 0)
    return;
  size_t remaining = tw->count - drop;
  if (remaining > 0) {
    memmove(tw->timestamps, tw->timestamps + drop, remaining * sizeof(double));
    memmove(tw->aux, tw->aux + drop, remaining * sizeof(int));
  }
  tw->count = remaining;
}

static void tw_clear(ad_time_window_t *tw) { tw->count = 0; }

/* O(n^2) dedup - fine given counts are bounded by the scan threshold (~tens of
 * entries). */
static size_t tw_distinct_aux_count(ad_time_window_t *tw) {
  size_t distinct = 0;
  for (size_t i = 0; i < tw->count; i++) {
    int dup = 0;
    for (size_t j = 0; j < i; j++)
      if (tw->aux[j] == tw->aux[i]) {
        dup = 1;
        break;
      }
    if (!dup)
      distinct++;
  }
  return distinct;
}

static void tw_free(ad_time_window_t *tw) {
  free(tw->timestamps);
  free(tw->aux);
  tw->timestamps = NULL;
  tw->aux = NULL;
  tw->count = tw->capacity = 0;
}

static ad_host_state_t *get_or_create(anomaly_detector_t *det, const char *ip) {
  unsigned long h = hash_str(ip) % AD_HASH_BUCKETS;
  for (ad_host_state_t *n = det->buckets[h]; n; n = n->next) {
    if (strcmp(n->ip, ip) == 0)
      return n;
  }
  ad_host_state_t *n = calloc(1, sizeof(ad_host_state_t));
  strncpy(n->ip, ip, sizeof(n->ip) - 1);
  n->next = det->buckets[h];
  det->buckets[h] = n;
  return n;
}

void anomdet_init_custom(anomaly_detector_t *det, event_logger_t *logger,
                         int port_scan_threshold, double port_scan_window,
                         int syn_flood_threshold, double syn_flood_window,
                         double zscore_threshold, double traffic_window) {
  memset(det, 0, sizeof(*det));
  pthread_mutex_init(&det->lock, NULL);
  det->logger = logger;
  det->port_scan_threshold = port_scan_threshold;
  det->port_scan_window = port_scan_window;
  det->syn_flood_threshold = syn_flood_threshold;
  det->syn_flood_window = syn_flood_window;
  det->zscore_threshold = zscore_threshold;
  det->traffic_window = traffic_window;
}

void anomdet_init(anomaly_detector_t *det, event_logger_t *logger) {
  anomdet_init_custom(det, logger, 15, 10.0, 100, 5.0, 3.0, 60.0);
}

void anomdet_destroy(anomaly_detector_t *det) {
  for (size_t i = 0; i < AD_HASH_BUCKETS; i++) {
    ad_host_state_t *n = det->buckets[i];
    while (n) {
      ad_host_state_t *next = n->next;
      tw_free(&n->port_activity);
      tw_free(&n->syn_activity);
      tw_free(&n->traffic_activity);
      free(n);
      n = next;
    }
    det->buckets[i] = NULL;
  }
  pthread_mutex_destroy(&det->lock);
}

static int check_port_scan(anomaly_detector_t *det, const char *src_ip,
                           int dst_port, double now, char *detail,
                           size_t detail_size) {
  ad_host_state_t *st = get_or_create(det, src_ip);
  tw_push(&st->port_activity, now, dst_port);
  tw_trim(&st->port_activity, now, det->port_scan_window);
  size_t distinct = tw_distinct_aux_count(&st->port_activity);
  if ((int)distinct >= det->port_scan_threshold) {
    tw_clear(&st->port_activity); /* avoid re-alerting every packet during the
                                     same scan */
    snprintf(detail, detail_size,
             "%zu distinct destination ports probed in %.0fs window", distinct,
             det->port_scan_window);
    return 1;
  }
  return 0;
}

static int check_syn_flood(anomaly_detector_t *det, const char *dst_ip,
                           double now, char *detail, size_t detail_size) {
  ad_host_state_t *st = get_or_create(det, dst_ip);
  tw_push(&st->syn_activity, now, 0);
  tw_trim(&st->syn_activity, now, det->syn_flood_window);
  if ((int)st->syn_activity.count >= det->syn_flood_threshold) {
    tw_clear(&st->syn_activity);
    snprintf(detail, detail_size,
             "%d+ SYN packets to %s within %.0fs (possible SYN flood / DoS)",
             det->syn_flood_threshold, dst_ip, det->syn_flood_window);
    return 1;
  }
  return 0;
}

static int check_traffic_volume(anomaly_detector_t *det, const char *host_ip,
                                double now, char *detail, size_t detail_size) {
  ad_host_state_t *st = get_or_create(det, host_ip);
  tw_push(&st->traffic_activity, now, 0);
  tw_trim(&st->traffic_activity, now, det->traffic_window);

  /* Sample the instantaneous rate at most once per second per host. */
  if (st->last_rate_sample_time != 0.0 && now - st->last_rate_sample_time < 1.0)
    return 0;
  st->last_rate_sample_time = now;

  double current_rate = (double)st->traffic_activity.count /
                        (det->traffic_window > 0 ? det->traffic_window : 1.0);

  int fired = 0;
  if (st->rate_history_count >= 10) {
    size_t n = st->rate_history_count;
    double mean = 0.0;
    for (size_t i = 0; i < n; i++)
      mean += st->rate_history[i];
    mean /= (double)n;
    double var = 0.0;
    for (size_t i = 0; i < n; i++) {
      double d = st->rate_history[i] - mean;
      var += d * d;
    }
    var /= (double)n;
    double stddev = sqrt(var);
    if (stddev > 0.0) {
      double z = (current_rate - mean) / stddev;
      if (z >= det->zscore_threshold && current_rate > 1.0) {
        snprintf(
            detail, detail_size,
            "Packet rate to %s is %.1f/s, z-score %.1f above %.0fs baseline",
            host_ip, current_rate, z, det->traffic_window);
        fired = 1;
      }
    }
  }

  if (st->rate_history_count < AD_RATE_HISTORY_MAX) {
    st->rate_history[st->rate_history_count++] = current_rate;
  } else {
    st->rate_history[st->rate_history_next] = current_rate;
    st->rate_history_next = (st->rate_history_next + 1) % AD_RATE_HISTORY_MAX;
  }
  return fired;
}

size_t anomdet_analyze(anomaly_detector_t *det, const parsed_packet_t *pkt,
                       anomaly_finding_t *out, size_t max_out) {
  double now = now_seconds();
  size_t count = 0;

  pthread_mutex_lock(&det->lock);

  if (pkt->src_ip[0] && pkt->dst_port >= 0 && count < max_out) {
    char detail[256];
    if (check_port_scan(det, pkt->src_ip, pkt->dst_port, now, detail,
                        sizeof(detail))) {
      anomaly_finding_t *f = &out[count++];
      memset(f, 0, sizeof(*f));
      strncpy(f->type, "port_scan", sizeof(f->type) - 1);
      f->severity = SEV_HIGH;
      strncpy(f->src_ip, pkt->src_ip, sizeof(f->src_ip) - 1);
      strncpy(f->detail, detail, sizeof(f->detail) - 1);
    }
  }

  if (strcmp(pkt->protocol, "tcp") == 0 && strchr(pkt->flags, 'S') &&
      !strchr(pkt->flags, 'A') && pkt->dst_ip[0] && count < max_out) {
    char detail[256];
    if (check_syn_flood(det, pkt->dst_ip, now, detail, sizeof(detail))) {
      anomaly_finding_t *f = &out[count++];
      memset(f, 0, sizeof(*f));
      strncpy(f->type, "syn_flood", sizeof(f->type) - 1);
      f->severity = SEV_CRITICAL;
      strncpy(f->dst_ip, pkt->dst_ip, sizeof(f->dst_ip) - 1);
      strncpy(f->detail, detail, sizeof(f->detail) - 1);
    }
  }

  if (pkt->dst_ip[0] && count < max_out) {
    char detail[256];
    if (check_traffic_volume(det, pkt->dst_ip, now, detail, sizeof(detail))) {
      anomaly_finding_t *f = &out[count++];
      memset(f, 0, sizeof(*f));
      strncpy(f->type, "traffic_spike", sizeof(f->type) - 1);
      f->severity = SEV_MEDIUM;
      strncpy(f->dst_ip, pkt->dst_ip, sizeof(f->dst_ip) - 1);
      strncpy(f->detail, detail, sizeof(f->detail) - 1);
    }
  }

  pthread_mutex_unlock(&det->lock);
  return count;
}
