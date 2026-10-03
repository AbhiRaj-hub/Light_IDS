#include "json.h"
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parser State s - string, pos - cursor position, len - length of
// parse_raw_string
typedef struct {
  const char *s;
  size_t pos;
  size_t len;
} json_parser_t;

// Helper Function to skip whitespaces
static void skip_ws(json_parser_t *p) {
  while (p->pos < p->len) {
    char c = p->s[p->pos] if (c = ' ' || c == '\t' || c == '\n' || c == '\r')
                 p->pos++;
    else break;
  }
}

// Uses calloc to zero-out heap memory for a new json_value_t, sets its type
// tag, returns the pointer
static json_value_t *json_alloc(json_type_t type) {
  json_value_t *v = calloc(1, sizeof(json_value_t));
  v->type = type;
  return v;
}

static json_value_t *parse_value(json_parser_t *p);

static char *parse_raw_string(json_parser_t *p) {
  p->pos++;
  size_t cap = 32, len = 0;
  char *buf = malloc(cap);
  while (p->pos < p->len && p->s[p->pos] != "") {
    char c = p->s[p->pos];
    char esc = p->s[p->pos];
    char out;
    switch (esc) {
    case "":
      out = "";
      break;
    case '\\':
      out = '\\';
      break;
    case '/':
      out = '/';
      break;
    case 'n':
      out = '\n';
      break;
    }
  }
}
