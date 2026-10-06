#define _GNU_SOURCE
#include "signature_detector.h"
#include "json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int sigdet_load(signature_detector_t *det, const char *rules_path,
                event_logger_t *logger) {
  det->count = 0;
  char *text = NULL;

  if (read_file(rules_path, &text) != 0) {
    if (logger)
      logger_log(logger, SEV_HIGH, "signature_detector",
                 "Failed to read rules file: %s", rules_path);
    return -1;
  }

  json_value_t *root = json_parse(text);
  free(text);

  if (!root) {
    if (logger)
      logger_log(logger, SEV_HIGH, "signature_detector",
                 "Failed to parse rules JSON: %s", rules_path);
    return -1;
  }

  json_value_t *rules_arr = json_object_get(root, "rules");
  size_t n = json_array_size(rules_arr);

  for (size_t i = 0; i < n && det->count < SIG_MAX_RULES; i++) {
    json_value_t *r = json_array_get(rules_arr, i);
    sig_rule_t *rule = &det->rules[det->count];
    memset(rule, 0, sizeof(*rule));

    strncpy(rule->id, json_get_string(r, "id", ""), sizeof(rule->id) - 1);
    strncpy(rule->name, json_get_string(r, "name", ""), sizeof(rule->name) - 1);
    strncpy(rule->description, json_get_string(r, "description", ""),
            sizeof(rule->description) - 1);
    rule->severity =
        severity_from_string(json_get_string(r, "severity", "low"));
    strncpy(rule->protocol, json_get_string(r, "protocol", ""),
            sizeof(rule->protocol) - 1);
    strncpy(rule->match_type, json_get_string(r, "match_type", ""),
            sizeof(rule->match_type) - 1);
    strncpy(rule->pattern, json_get_string(r, "pattern", ""),
            sizeof(rule->pattern) - 1);
    strncpy(rule->mitre_attack, json_get_string(r, "mitre_attack", ""),
            sizeof(rule->mitre_attack) - 1);
    rule->has_compiled_regex = 0;

    if (strcmp(rule->match_type, "payload_regex") == 0) {
      int rc = regcomp(&rule->compiled_regex, rule->pattern,
                       REG_EXTENDED | REG_ICASE);
      if (rc != 0) {
        char errbuf[256];
        regerror(rc, &rule->compiled_regex, errbuf, sizeof(errbuf));
        if (logger)
          logger_log(logger, SEV_HIGH, "signature_detector",
                     "Rule %s: failed to compile regex, skipping: %s", rule->id,
                     errbuf);
        continue; /* don't advance det->count; next rule overwrites this slot */
      }
      rule->has_compiled_regex = 1;
    }
    det->count++;
  }

  json_free(root);
  if (logger)
    logger_log(logger, SEV_INFO, "signature_detector",
               "Loaded %zu signature rules", det->count);
  return 0;
}

void sigdet_free(signature_detector_t *det) {
  for (size_t i = 0; i < det->count; i++) {
    if (det->rules[i].has_compiled_regex)
      regfree(&det->rules[i].compiled_regex);
  }
  det->count = 0;
}

/* Copies payload into a NUL-terminated buffer for regexec()/strcasestr(),
 * replacing embedded NUL bytes with a space so a binary payload doesn't
 * truncate the match early. */
static void payload_to_cstr(const parsed_packet_t *pkt, char *buf,
                            size_t bufsize) {
  size_t n = pkt->payload_len;
  if (n > bufsize - 1)
    n = bufsize - 1;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = pkt->payload[i];
    buf[i] = (c == 0) ? ' ' : (char)c;
  }
  buf[n] = '\0';
}

static int match_payload_regex(const sig_rule_t *rule, const char *text) {
  if (!rule->has_compiled_regex || text[0] == '\0')
    return 0;
  return regexec(&rule->compiled_regex, text, 0, NULL, 0) == 0;
}

static int match_contains(const sig_rule_t *rule, const char *text) {
  if (text[0] == '\0')
    return 0;
  return strcasestr(text, rule->pattern) != NULL;
}

static int match_port(const sig_rule_t *rule, const parsed_packet_t *pkt) {
  int target = atoi(rule->pattern);
  return pkt->src_port == target || pkt->dst_port == target;
}

/* Order-independent character-set equality, mirroring Python's set(flags) ==
 * set(pattern). */
static int charset_equal(const char *a, const char *b) {
  int seen_a[256] = {0}, seen_b[256] = {0};
  for (const char *p = a; *p; p++)
    seen_a[(unsigned char)*p] = 1;
  for (const char *p = b; *p; p++)
    seen_b[(unsigned char)*p] = 1;
  for (int i = 0; i < 256; i++)
    if (seen_a[i] != seen_b[i])
      return 0;
  return 1;
}

static int match_flags(const sig_rule_t *rule, const parsed_packet_t *pkt) {
  if (strcmp(rule->pattern, "NULL") == 0)
    return pkt->flags[0] == '\0';
  return charset_equal(pkt->flags, rule->pattern);
}

size_t sigdet_inspect(signature_detector_t *det, const parsed_packet_t *pkt,
                      const sig_rule_t **out, size_t max_out) {
  size_t found = 0;
  char payload_buf[4096];
  int payload_ready = 0;

  for (size_t i = 0; i < det->count && found < max_out; i++) {
    sig_rule_t *rule = &det->rules[i];
    if (rule->protocol[0] != '\0' && strcmp(rule->protocol, pkt->protocol) != 0)
      continue;

    int matched = 0;
    if (strcmp(rule->match_type, "payload_regex") == 0) {
      if (!payload_ready) {
        payload_to_cstr(pkt, payload_buf, sizeof(payload_buf));
        payload_ready = 1;
      }
      matched = match_payload_regex(rule, payload_buf);
    } else if (strcmp(rule->match_type, "payload_contains") == 0) {
      if (!payload_ready) {
        payload_to_cstr(pkt, payload_buf, sizeof(payload_buf));
        payload_ready = 1;
      }
      matched = match_contains(rule, payload_buf);
    } else if (strcmp(rule->match_type, "port_match") == 0) {
      matched = match_port(rule, pkt);
    } else if (strcmp(rule->match_type, "flag_match") == 0) {
      matched = match_flags(rule, pkt);
    }

    if (matched)
      out[found++] = rule;
  }
  return found;
}
