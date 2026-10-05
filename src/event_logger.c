#define _GNU_SOURCE
#include "event_logger.h"
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

static const char *COLOR_DEBUG = "\033[90m";
static const char *COLOR_INFO = "\033[36m";
static const char *COLOR_LOW = "\033[32m";
static const char *COLOR_MEDIUM = "\033[33m";
static const char *COLOR_HIGH = "\033[31m";
static const char *COLOR_CRITICAL = "\033[41m\033[97m";
static const char *COLOR_RESET = "\033[0m";

severity_t severity_from_string(const char *s) {
  if (!s)
    return SEV_INFO;
  if (strcmp(s, "debug") == 0)
    return SEV_DEBUG;
  if (strcmp(s, "info") == 0)
    return SEV_INFO;
  if (strcmp(s, "low") == 0)
    return SEV_LOW;
  if (strcmp(s, "medium") == 0)
    return SEV_MEDIUM;
  if (strcmp(s, "high") == 0)
    return SEV_HIGH;
  if (strcmp(s, "critical") == 0)
    return SEV_CRITICAL;
  return SEV_INFO;
}

const char *severity_to_string(severity_t sev) {
  switch (sev) {
  case SEV_DEBUG:
    return "debug";
  case SEV_INFO:
    return "info";
  case SEV_LOW:
    return "low";
  case SEV_MEDIUM:
    return "medium";
  case SEV_HIGH:
    return "high";
  case SEV_CRITICAL:
    return "critical";
  default:
    return "info";
  }
}

static const char *severity_color(severity_t sev) {
  switch (sev) {
  case SEV_DEBUG:
    return COLOR_DEBUG;
  case SEV_INFO:
    return COLOR_INFO;
  case SEV_LOW:
    return COLOR_LOW;
  case SEV_MEDIUM:
    return COLOR_MEDIUM;
  case SEV_HIGH:
    return COLOR_HIGH;
  case SEV_CRITICAL:
    return COLOR_CRITICAL;
  default:
    return COLOR_INFO;
  }
}

static void iso8601_now(char *buf, size_t bufsize) {
  time_t t = time(NULL);
  struct tm tmv;
  gmtime_r(&t, &tmv);
  strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%S+00:00", &tmv);
}

int logger_init(event_logger_t *logger, const char *log_dir,
                const char *log_file, int console_output,
                severity_t min_console_severity) {
  memset(logger, 0, sizeof(*logger));
  strncpy(logger->log_dir, log_dir, sizeof(logger->log_dir) - 1);
  logger->console_output = console_output;
  logger->min_console_severity = min_console_severity;
  pthread_mutex_init(&logger->lock, NULL);

  if (mkdir(log_dir, 0755) != 0 && errno != EEXIST) {
    fprintf(stderr, "Warning: could not create log directory '%s': %s\n",
            log_dir, strerror(errno));
  }
  snprintf(logger->log_path, sizeof(logger->log_path), "%s/%s", log_dir,
           log_file);
  return 0;
}

void logger_destroy(event_logger_t *logger) {
  pthread_mutex_destroy(&logger->lock);
}

static void write_record(event_logger_t *logger, severity_t sev,
                         const char *json_line, const char *console_msg,
                         const char *source) {
  pthread_mutex_lock(&logger->lock);
  FILE *f = fopen(logger->log_path, "a");
  if (f) {
    fprintf(f, "%s\n", json_line);
    fclose(f);
  }
  if (logger->console_output && sev >= logger->min_console_severity) {
    char ts[64];
    iso8601_now(ts, sizeof(ts));
    FILE *stream = (sev >= SEV_HIGH) ? stderr : stdout;
    char sevbuf[12];
    snprintf(sevbuf, sizeof(sevbuf), "%-8s", severity_to_string(sev));
    for (char *p = sevbuf; *p; p++)
      *p = (char)toupper((unsigned char)*p);
    fprintf(stream, "%s[%s] [%s] [%s] %s%s\n", severity_color(sev), ts, sevbuf,
            source, console_msg, COLOR_RESET);
  }
  pthread_mutex_unlock(&logger->lock);
}

void logger_log(event_logger_t *logger, severity_t sev, const char *source,
                const char *fmt, ...) {
  char message[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(message, sizeof(message), fmt, ap);
  va_end(ap);

  char ts[64];
  iso8601_now(ts, sizeof(ts));
  char esc_msg[1200];
  ids_json_escape(message, esc_msg, sizeof(esc_msg));

  char line[1536];
  snprintf(line, sizeof(line),
           "{\"timestamp\": \"%s\", \"severity\": \"%s\", \"source\": \"%s\", "
           "\"message\": \"%s\"}",
           ts, severity_to_string(sev), source, esc_msg);

  write_record(logger, sev, line, message, source);
}

void logger_alert(event_logger_t *logger, const char *rule_id,
                  const char *rule_name, severity_t sev, const char *src_ip,
                  const char *dst_ip, const char *proto,
                  const char *description, const char *mitre_attack) {
  char ts[64];
  iso8601_now(ts, sizeof(ts));

  char console_msg[512];
  snprintf(console_msg, sizeof(console_msg), "%s (%s) - %s -> %s [%s]",
           rule_name ? rule_name : "", rule_id ? rule_id : "",
           src_ip ? src_ip : "-", dst_ip ? dst_ip : "-", proto ? proto : "-");

  char esc_console_msg[600];
  ids_json_escape(console_msg, esc_console_msg, sizeof(esc_console_msg));
  char esc_name[300];
  ids_json_escape(rule_name ? rule_name : "", esc_name, sizeof(esc_name));
  char esc_desc[600];
  ids_json_escape(description ? description : "", esc_desc, sizeof(esc_desc));

  char mitre_field[64];
  if (mitre_attack && mitre_attack[0])
    snprintf(mitre_field, sizeof(mitre_field), "\"%s\"", mitre_attack);
  else
    snprintf(mitre_field, sizeof(mitre_field), "null");

  char line[2048];
  snprintf(
      line, sizeof(line),
      "{\"timestamp\": \"%s\", \"severity\": \"%s\", \"source\": \"detector\", "
      "\"message\": \"%s\", \"event_type\": \"alert\", \"rule_id\": \"%s\", "
      "\"rule_name\": \"%s\", \"src_ip\": \"%s\", \"dst_ip\": \"%s\", "
      "\"protocol\": \"%s\", \"description\": \"%s\", \"mitre_attack\": %s}",
      ts, severity_to_string(sev), esc_console_msg, rule_id ? rule_id : "",
      esc_name, src_ip ? src_ip : "", dst_ip ? dst_ip : "", proto ? proto : "",
      esc_desc, mitre_field);

  write_record(logger, sev, line, console_msg, "detector");
}
