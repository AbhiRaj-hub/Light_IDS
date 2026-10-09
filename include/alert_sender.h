#ifndef IDS_ALERT_SENDER_H
#define IDS_ALERT_SENDER_H

#include "event_logger.h"
#include <pthread.h>

#define AS_MAX_RCPTS 8

typedef struct {
  int enabled;
  char smtp_host[256];
  int smtp_port;
  int use_tls; /* accepted for config compatibility; not implemented (see
                  README) */
  char username[256];
  char password[256];
  char from_addr[256];
  char to_addrs[AS_MAX_RCPTS][256];
  int to_addrs_count;
} email_config_t;

typedef struct {
  int enabled;
  char webhook_url[512];
} slack_config_t;

typedef struct {
  int enabled;
  char url[512];
} webhook_config_t;

typedef struct {
  email_config_t email;
  slack_config_t slack;
  webhook_config_t webhook;
  severity_t min_severity;
  int rate_limit_max_events;
  double rate_limit_window_seconds;
} alert_config_t;

typedef struct {
  char rule_id[64];
  double *timestamps;
  size_t count;
  size_t capacity;
} rl_entry_t;

typedef struct {
  rl_entry_t *entries;
  size_t count;
  size_t capacity;
  int max_events;
  double window_seconds;
  pthread_mutex_t lock;
} rate_limiter_t;

typedef struct {
  alert_config_t config;
  rate_limiter_t limiter;
  event_logger_t *logger;
} alert_sender_t;

typedef struct {
  char rule_id[64];
  char rule_name[128];
  severity_t severity;
  char src_ip[64];
  char dst_ip[64];
  char protocol[16];
  char description[300];
  char mitre_attack[32];
  double timestamp;
} alert_t;

int alertsender_load_config(alert_config_t *cfg, const char *config_path,
                            event_logger_t *logger);
void alertsender_init(alert_sender_t *sender, alert_config_t cfg,
                      event_logger_t *logger);
void alertsender_destroy(alert_sender_t *sender);

/* Non-blocking: spawns a detached worker thread per alert. */
void alertsender_dispatch(alert_sender_t *sender, const alert_t *alert);

#endif
