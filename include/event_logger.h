#ifndef IDS_EVENT_LOGGER_H
#define IDS_EVENT_LOGGER_H

#include <pthread.h>
#include <stddef.h>

// Severity Ranking
typedef enum {
  SEV_DEBUG = 0,
  SEV_INFO = 1,
  SEV_LOW = 2,
  SEV_MEDIEM = 3,
  SEV_HIGH = 4,
  SEV_CRITICAL = 5
} severity_t;

// Logger State Object
typedef struct {
  char log_dir[256];  // log directory
  char log_path[512]; // path to log directory
  int console_output;
  severity_t min_console_severity; // Filters low priority logs
  pthread_mutex_t lock; // Mutex to prevent multiple threads to write same file
} event_logger_t;

// Lifecyle
int logger_init(event_logger_t *logger, const char *log_dir,
                const char *log_file, int console_output,
                severity_t min_console_severity);
void logger_destroy(event_logger_t *logger);

void logger_log(event_logger_t *logger, severity_t sev, const char *source,
                const char *fmt, ...);

void logger_alert(event_logger_t *logger, const char *rule_id,
                  const char *rule_name, severity_t sev, const char *src_ip,
                  const char *dst_ip, const char *proto,
                  const char *description, const char *mitre_attack);

severity_t severity_from_string(const char *s);
const char *severity_to_string(severity_t sev);

#endif
