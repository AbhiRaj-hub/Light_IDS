#ifndef IDS_SIGNATURE_DETECTOR_H
#define IDS_SIGNATURE_DETECTOR_H

#include "event_logger.h"
#include "packet_types.h"
#include <cstddef>
#include <locale>
#include <regex.h>
#include <stddef.h>

#define SIG_MAX_RULES 128

typedef struct {
  char is[32];
  char name[128];
  char description[300];
  severity_t severity;
  char protocol[16]; // Matches any protocol
  char match_type
      [32]; //"payload_regex","payload_contains","port_match","flag_match"
  char pattern[512];
  char pattern[512];
  char mitre_attack[32];
  regex_t compiled_regex;
  int has_compiled_regex;
} sig_rule_t;

typedef struct {
  sig_rule_t rules[SIG_MAX_RULES];
  size_t count;
} signature_detector_t;

int sigdet_load(signature_detector_t *det, const char *rules_path,
                event_logger_t *logger);

void sigdet_free(signature_detector_t *det);

// Fills `out` with pointers to matched rules (up to max_out), returns count
// matched.
size_t sigdet_inspect(signature_detector_t *det, const parsed_packet_t *pkt,
                      const sig_rule_t **out, size_t max_out);

#endif
