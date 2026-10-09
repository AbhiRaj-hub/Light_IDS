#define _GNU_SOURCE
#include "alert_sender.h"
#include "json.h"
#include "util.h"
#include <curl/curl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>


static double now_seconds(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/* ---------------------------- config loading ---------------------------- */

static int read_file(const char *path, char **out_text) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz < 0) {
    fclose(f);
    return -1;
  }
  char *buf = malloc((size_t)sz + 1);
  size_t rd = fread(buf, 1, (size_t)sz, f);
  buf[rd] = '\0';
  fclose(f);
  *out_text = buf;
  return 0;
}

static void set_default_config(alert_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->min_severity = SEV_MEDIUM;
  cfg->rate_limit_max_events = 5;
  cfg->rate_limit_window_seconds = 60.0;
}

int alertsender_load_config(alert_config_t *cfg, const char *config_path,
                            event_logger_t *logger) {
  set_default_config(cfg);
  char *text = NULL;
  if (read_file(config_path, &text) != 0) {
    if (logger)
      logger_log(logger, SEV_INFO, "alert_sender",
                 "No alerting config found at %s, all channels stay disabled",
                 config_path);
    return 0; /* not fatal: defaults leave everything disabled */
  }
  json_value_t *root = json_parse(text);
  free(text);
  if (!root) {
    if (logger)
      logger_log(logger, SEV_HIGH, "alert_sender",
                 "Failed to parse alerting config: %s", config_path);
    return -1;
  }

  json_value_t *email = json_object_get(root, "email");
  if (email) {
    cfg->email.enabled = json_get_bool(email, "enabled", 0);
    strncpy(cfg->email.smtp_host, json_get_string(email, "smtp_host", ""),
            sizeof(cfg->email.smtp_host) - 1);
    cfg->email.smtp_port = (int)json_get_number(email, "smtp_port", 587);
    cfg->email.use_tls = json_get_bool(email, "use_tls", 1);
    strncpy(cfg->email.username, json_get_string(email, "username", ""),
            sizeof(cfg->email.username) - 1);
    strncpy(cfg->email.password, json_get_string(email, "password", ""),
            sizeof(cfg->email.password) - 1);
    strncpy(cfg->email.from_addr, json_get_string(email, "from_addr", ""),
            sizeof(cfg->email.from_addr) - 1);
    json_value_t *to_arr = json_object_get(email, "to_addrs");
    size_t n = json_array_size(to_arr);
    if (n > AS_MAX_RCPTS)
      n = AS_MAX_RCPTS;
    for (size_t i = 0; i < n; i++) {
      json_value_t *item = json_array_get(to_arr, i);
      if (item && item->type == JSON_STRING) {
        strncpy(cfg->email.to_addrs[cfg->email.to_addrs_count], item->u.string,
                sizeof(cfg->email.to_addrs[0]) - 1);
        cfg->email.to_addrs_count++;
      }
    }
  }

  json_value_t *slack = json_object_get(root, "slack");
  if (slack) {
    cfg->slack.enabled = json_get_bool(slack, "enabled", 0);
    strncpy(cfg->slack.webhook_url, json_get_string(slack, "webhook_url", ""),
            sizeof(cfg->slack.webhook_url) - 1);
  }

  json_value_t *webhook = json_object_get(root, "webhook");
  if (webhook) {
    cfg->webhook.enabled = json_get_bool(webhook, "enabled", 0);
    strncpy(cfg->webhook.url, json_get_string(webhook, "url", ""),
            sizeof(cfg->webhook.url) - 1);
  }

  cfg->min_severity =
      severity_from_string(json_get_string(root, "min_severity", "medium"));

  json_value_t *rl = json_object_get(root, "rate_limit");
  if (rl) {
    cfg->rate_limit_max_events = (int)json_get_number(rl, "max_events", 5);
    cfg->rate_limit_window_seconds =
        json_get_number(rl, "window_seconds", 60.0);
  }

  json_free(root);
  return 0;
}

/* ------------------------------ rate limiter ----------------------------- */

static rl_entry_t *rl_find_or_create(rate_limiter_t *rl, const char *rule_id) {
  for (size_t i = 0; i < rl->count; i++) {
    if (strcmp(rl->entries[i].rule_id, rule_id) == 0)
      return &rl->entries[i];
  }
  if (rl->count >= rl->capacity) {
    size_t newcap = rl->capacity ? rl->capacity * 2 : 16;
    rl->entries = realloc(rl->entries, newcap * sizeof(rl_entry_t));
    rl->capacity = newcap;
  }
  rl_entry_t *e = &rl->entries[rl->count++];
  memset(e, 0, sizeof(*e));
  strncpy(e->rule_id, rule_id, sizeof(e->rule_id) - 1);
  return e;
}

static int rl_allow(rate_limiter_t *rl, const char *rule_id) {
  double now = now_seconds();
  pthread_mutex_lock(&rl->lock);
  rl_entry_t *e = rl_find_or_create(rl, rule_id);

  size_t drop = 0;
  while (drop < e->count && (now - e->timestamps[drop]) > rl->window_seconds)
    drop++;
  if (drop > 0) {
    size_t remaining = e->count - drop;
    if (remaining > 0)
      memmove(e->timestamps, e->timestamps + drop, remaining * sizeof(double));
    e->count = remaining;
  }

  if ((int)e->count >= rl->max_events) {
    pthread_mutex_unlock(&rl->lock);
    return 0;
  }
  if (e->count >= e->capacity) {
    size_t newcap = e->capacity ? e->capacity * 2 : 8;
    e->timestamps = realloc(e->timestamps, newcap * sizeof(double));
    e->capacity = newcap;
  }
  e->timestamps[e->count++] = now;
  pthread_mutex_unlock(&rl->lock);
  return 1;
}

/* -------------------------------- lifecycle ------------------------------ */

void alertsender_init(alert_sender_t *sender, alert_config_t cfg,
                      event_logger_t *logger) {
  memset(sender, 0, sizeof(*sender));
  sender->config = cfg;
  sender->logger = logger;
  sender->limiter.max_events = cfg.rate_limit_max_events;
  sender->limiter.window_seconds = cfg.rate_limit_window_seconds;
  pthread_mutex_init(&sender->limiter.lock, NULL);
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

void alertsender_destroy(alert_sender_t *sender) {
  for (size_t i = 0; i < sender->limiter.count; i++)
    free(sender->limiter.entries[i].timestamps);
  free(sender->limiter.entries);
  pthread_mutex_destroy(&sender->limiter.lock);
  curl_global_cleanup();
}

/* ------------------------------- formatting ------------------------------ */

static void format_message(const alert_t *a, char *out, size_t outsize) {
  snprintf(out, outsize,
           "[%s] %s (%s)\nSrc: %s -> Dst: %s  Proto: %s\nMITRE ATT&CK: "
           "%s\nDetail: %s\nTime: %.0f",
           severity_to_string(a->severity), a->rule_name, a->rule_id,
           a->src_ip[0] ? a->src_ip : "-", a->dst_ip[0] ? a->dst_ip : "-",
           a->protocol, a->mitre_attack[0] ? a->mitre_attack : "N/A",
           a->description, a->timestamp);
}

/* -------------------------------- channels -------------------------------- */

static size_t curl_discard_cb(void *ptr, size_t size, size_t nmemb,
                              void *userdata) {
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static void send_slack(alert_sender_t *sender, const alert_t *a) {
  char msg[900];
  format_message(a, msg, sizeof(msg));
  char esc[1100];
  ids_json_escape(msg, esc, sizeof(esc));
  char body[1200];
  snprintf(body, sizeof(body), "{\"text\": \"%s\"}", esc);

  CURL *curl = curl_easy_init();
  if (!curl) {
    if (sender->logger)
      logger_log(sender->logger, SEV_HIGH, "alert_sender",
                 "curl_easy_init failed for slack");
    return;
  }
  struct curl_slist *headers =
      curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_URL, sender->config.slack.webhook_url);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_discard_cb);
  CURLcode rc = curl_easy_perform(curl);
  if (rc != CURLE_OK && sender->logger) {
    logger_log(sender->logger, SEV_HIGH, "alert_sender",
               "Slack alert failed: %s", curl_easy_strerror(rc));
  }
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
}

static void send_webhook(alert_sender_t *sender, const alert_t *a) {
  char esc_name[300], esc_desc[600];
  ids_json_escape(a->rule_name, esc_name, sizeof(esc_name));
  ids_json_escape(a->description, esc_desc, sizeof(esc_desc));

  char body[2048];
  snprintf(
      body, sizeof(body),
      "{\"rule_id\": \"%s\", \"rule_name\": \"%s\", \"severity\": \"%s\", "
      "\"src_ip\": \"%s\", \"dst_ip\": \"%s\", \"protocol\": \"%s\", "
      "\"description\": \"%s\", \"mitre_attack\": \"%s\", \"timestamp\": %.3f}",
      a->rule_id, esc_name, severity_to_string(a->severity), a->src_ip,
      a->dst_ip, a->protocol, esc_desc, a->mitre_attack, a->timestamp);

  CURL *curl = curl_easy_init();
  if (!curl) {
    if (sender->logger)
      logger_log(sender->logger, SEV_HIGH, "alert_sender",
                 "curl_easy_init failed for webhook");
    return;
  }
  struct curl_slist *headers =
      curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_URL, sender->config.webhook.url);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_discard_cb);
  CURLcode rc = curl_easy_perform(curl);
  if (rc != CURLE_OK && sender->logger) {
    logger_log(sender->logger, SEV_HIGH, "alert_sender",
               "Webhook alert failed: %s", curl_easy_strerror(rc));
  }
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
}

/* Minimal plaintext SMTP client - no STARTTLS/TLS. Point smtp_host at a local
 * relay/MTA (e.g. localhost:25 via postfix in relay mode) for real deployments,
 * or extend send_email() with OpenSSL. See README "Known Limitations". */

static int smtp_connect(const char *host, int port) {
  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%d", port);
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, portstr, &hints, &res) != 0)
    return -1;
  int fd = -1;
  for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0)
      continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

static int smtp_read_response(int fd, char *buf, size_t bufsize) {
  size_t total = 0;
  for (;;) {
    if (total + 1 >= bufsize)
      break;
    ssize_t n = recv(fd, buf + total, bufsize - total - 1, 0);
    if (n <= 0)
      break;
    total += (size_t)n;
    buf[total] = '\0';
    if (total >= 4) {
      size_t i = total;
      while (i > 0 && buf[i - 1] != '\n')
        i--;
      if (total - i >= 4 && buf[i + 3] == ' ')
        break; /* "250 " terminator, not "250-" continuation */
    }
  }
  return (int)total;
}

static void smtp_send_cmd(int fd, const char *cmd) {
  send(fd, cmd, strlen(cmd), 0);
}

static void send_email(alert_sender_t *sender, const alert_t *a) {
  email_config_t *cfg = &sender->config.email;
  if (cfg->use_tls && sender->logger) {
    logger_log(
        sender->logger, SEV_MEDIUM, "alert_sender",
        "Email channel: use_tls is set but this build has no TLS support; "
        "attempting a plaintext SMTP session anyway (point smtp_host at a "
        "local relay/MTA)");
  }

  int fd = smtp_connect(cfg->smtp_host, cfg->smtp_port);
  if (fd < 0) {
    if (sender->logger)
      logger_log(sender->logger, SEV_HIGH, "alert_sender",
                 "Failed to connect to SMTP host %s:%d", cfg->smtp_host,
                 cfg->smtp_port);
    return;
  }

  char resp[1024];
  char cmd[1024];

  smtp_read_response(fd, resp, sizeof(resp)); /* banner */

  snprintf(cmd, sizeof(cmd), "EHLO localhost\r\n");
  smtp_send_cmd(fd, cmd);
  smtp_read_response(fd, resp, sizeof(resp));

  if (cfg->username[0]) {
    smtp_send_cmd(fd, "AUTH LOGIN\r\n");
    smtp_read_response(fd, resp, sizeof(resp));

    char b64[512];
    ids_base64_encode((const unsigned char *)cfg->username,
                      strlen(cfg->username), b64, sizeof(b64));
    snprintf(cmd, sizeof(cmd), "%s\r\n", b64);
    smtp_send_cmd(fd, cmd);
    smtp_read_response(fd, resp, sizeof(resp));

    ids_base64_encode((const unsigned char *)cfg->password,
                      strlen(cfg->password), b64, sizeof(b64));
    snprintf(cmd, sizeof(cmd), "%s\r\n", b64);
    smtp_send_cmd(fd, cmd);
    smtp_read_response(fd, resp, sizeof(resp));
  }

  snprintf(cmd, sizeof(cmd), "MAIL FROM:<%s>\r\n", cfg->from_addr);
  smtp_send_cmd(fd, cmd);
  smtp_read_response(fd, resp, sizeof(resp));

  for (int i = 0; i < cfg->to_addrs_count; i++) {
    snprintf(cmd, sizeof(cmd), "RCPT TO:<%s>\r\n", cfg->to_addrs[i]);
    smtp_send_cmd(fd, cmd);
    smtp_read_response(fd, resp, sizeof(resp));
  }

  smtp_send_cmd(fd, "DATA\r\n");
  smtp_read_response(fd, resp, sizeof(resp));

  char body[1200];
  format_message(a, body, sizeof(body));

  char to_line[600] = {0};
  for (int i = 0; i < cfg->to_addrs_count; i++) {
    strncat(to_line, cfg->to_addrs[i], sizeof(to_line) - strlen(to_line) - 1);
    if (i < cfg->to_addrs_count - 1)
      strncat(to_line, ", ", sizeof(to_line) - strlen(to_line) - 1);
  }

  char data[2048];
  snprintf(
      data, sizeof(data),
      "Subject: [IDS ALERT][%s] %s\r\nFrom: %s\r\nTo: %s\r\n\r\n%s\r\n.\r\n",
      severity_to_string(a->severity), a->rule_name, cfg->from_addr, to_line,
      body);
  smtp_send_cmd(fd, data);
  smtp_read_response(fd, resp, sizeof(resp));

  smtp_send_cmd(fd, "QUIT\r\n");
  close(fd);
}

/* --------------------------------- dispatch --------------------------------
 */

typedef struct {
  alert_sender_t *sender;
  alert_t alert;
} worker_arg_t;

static void *worker_thread(void *arg) {
  worker_arg_t *wa = (worker_arg_t *)arg;
  alert_sender_t *sender = wa->sender;
  alert_t *a = &wa->alert;

  /* One worker thread per alert handles every enabled channel sequentially -
   * simpler than one thread per channel while still never blocking capture. */
  if (sender->config.email.enabled)
    send_email(sender, a);
  if (sender->config.slack.enabled)
    send_slack(sender, a);
  if (sender->config.webhook.enabled)
    send_webhook(sender, a);

  free(wa);
  return NULL;
}

static int meets_threshold(severity_t sev, severity_t min_sev) {
  return sev >= min_sev;
}

void alertsender_dispatch(alert_sender_t *sender, const alert_t *alert) {
  if (!meets_threshold(alert->severity, sender->config.min_severity))
    return;
  if (!rl_allow(&sender->limiter, alert->rule_id)) {
    if (sender->logger)
      logger_log(sender->logger, SEV_DEBUG, "alert_sender",
                 "Rate-limited alert for %s", alert->rule_id);
    return;
  }
  if (!sender->config.email.enabled && !sender->config.slack.enabled &&
      !sender->config.webhook.enabled)
    return;

  worker_arg_t *wa = malloc(sizeof(worker_arg_t));
  wa->sender = sender;
  wa->alert = *alert;

  pthread_t tid;
  if (pthread_create(&tid, NULL, worker_thread, wa) != 0) {
    if (sender->logger)
      logger_log(sender->logger, SEV_HIGH, "alert_sender",
                 "Failed to spawn alert worker thread");
    free(wa);
    return;
  }
  pthread_detach(tid);
}
