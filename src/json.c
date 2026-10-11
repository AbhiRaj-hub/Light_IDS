#include "json.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
  const char *s;
  size_t pos;
  size_t len;
} json_parser_t;

static void skip_ws(json_parser_t *p) {
  while (p->pos < p->len) {
    char c = p->s[p->pos];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
      p->pos++;
    else
      break;
  }
}

static json_value_t *json_alloc(json_type_t type) {
  json_value_t *v = calloc(1, sizeof(json_value_t));
  v->type = type;
  return v;
}

static json_value_t *parse_value(json_parser_t *p);

static char *parse_raw_string(json_parser_t *p) {
  /* assumes p->s[p->pos] == '"' */
  p->pos++;
  size_t cap = 32, len = 0;
  char *buf = malloc(cap);
  while (p->pos < p->len && p->s[p->pos] != '"') {
    char c = p->s[p->pos];
    if (c == '\\' && p->pos + 1 < p->len) {
      p->pos++;
      char esc = p->s[p->pos];
      char out;
      switch (esc) {
      case '"':
        out = '"';
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
      case 't':
        out = '\t';
        break;
      case 'r':
        out = '\r';
        break;
      case 'b':
        out = '\b';
        break;
      case 'f':
        out = '\f';
        break;
      case 'u': {
        /* Skip \uXXXX; we only need ASCII for our own config files,
           so emit a placeholder rather than full UTF-8 decoding. */
        p->pos++;
        for (int i = 0; i < 4 && p->pos < p->len; i++)
          p->pos++;
        p->pos--;
        out = '?';
        break;
      }
      default:
        out = esc;
        break;
      }
      if (len + 1 >= cap) {
        cap *= 2;
        buf = realloc(buf, cap);
      }
      buf[len++] = out;
      p->pos++;
    } else {
      if (len + 1 >= cap) {
        cap *= 2;
        buf = realloc(buf, cap);
      }
      buf[len++] = c;
      p->pos++;
    }
  }
  if (p->pos < p->len)
    p->pos++; /* closing quote */
  buf[len] = '\0';
  return buf;
}

static json_value_t *parse_string_value(json_parser_t *p) {
  json_value_t *v = json_alloc(JSON_STRING);
  v->u.string = parse_raw_string(p);
  return v;
}

static json_value_t *parse_number(json_parser_t *p) {
  size_t start = p->pos;
  if (p->s[p->pos] == '-')
    p->pos++;
  while (p->pos < p->len && isdigit((unsigned char)p->s[p->pos]))
    p->pos++;
  if (p->pos < p->len && p->s[p->pos] == '.') {
    p->pos++;
    while (p->pos < p->len && isdigit((unsigned char)p->s[p->pos]))
      p->pos++;
  }
  if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
    p->pos++;
    if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-'))
      p->pos++;
    while (p->pos < p->len && isdigit((unsigned char)p->s[p->pos]))
      p->pos++;
  }
  size_t len = p->pos - start;
  char *tmp = malloc(len + 1);
  memcpy(tmp, p->s + start, len);
  tmp[len] = '\0';
  json_value_t *v = json_alloc(JSON_NUMBER);
  v->u.number = atof(tmp);
  free(tmp);
  return v;
}

static json_value_t *parse_object(json_parser_t *p) {
  json_value_t *v = json_alloc(JSON_OBJECT);
  p->pos++; /* '{' */
  skip_ws(p);
  json_member_t *head = NULL, *tail = NULL;
  if (p->pos < p->len && p->s[p->pos] == '}') {
    p->pos++;
    v->u.object = NULL;
    return v;
  }
  while (p->pos < p->len) {
    skip_ws(p);
    if (p->pos >= p->len || p->s[p->pos] != '"')
      break; /* malformed: bail */
    char *key = parse_raw_string(p);
    skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == ':')
      p->pos++;
    skip_ws(p);
    json_value_t *val = parse_value(p);
    json_member_t *m = calloc(1, sizeof(json_member_t));
    m->key = key;
    m->value = val;
    m->next = NULL;
    if (!head) {
      head = tail = m;
    } else {
      tail->next = m;
      tail = m;
    }
    skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == ',') {
      p->pos++;
      continue;
    }
    if (p->pos < p->len && p->s[p->pos] == '}') {
      p->pos++;
      break;
    }
    break;
  }
  v->u.object = head;
  return v;
}

static json_value_t *parse_array(json_parser_t *p) {
  json_value_t *v = json_alloc(JSON_ARRAY);
  p->pos++; /* '[' */
  skip_ws(p);
  size_t cap = 8, count = 0;
  json_value_t **items = malloc(cap * sizeof(json_value_t *));
  if (p->pos < p->len && p->s[p->pos] == ']') {
    p->pos++;
    v->u.array.items = items;
    v->u.array.count = 0;
    return v;
  }
  while (p->pos < p->len) {
    skip_ws(p);
    json_value_t *item = parse_value(p);
    if (count >= cap) {
      cap *= 2;
      items = realloc(items, cap * sizeof(json_value_t *));
    }
    items[count++] = item;
    skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == ',') {
      p->pos++;
      continue;
    }
    if (p->pos < p->len && p->s[p->pos] == ']') {
      p->pos++;
      break;
    }
    break;
  }
  v->u.array.items = items;
  v->u.array.count = count;
  return v;
}

static json_value_t *parse_value(json_parser_t *p) {
  skip_ws(p);
  if (p->pos >= p->len)
    return json_alloc(JSON_NULL);
  char c = p->s[p->pos];
  if (c == '{')
    return parse_object(p);
  if (c == '[')
    return parse_array(p);
  if (c == '"')
    return parse_string_value(p);
  if (c == 't' && p->pos + 4 <= p->len &&
      strncmp(p->s + p->pos, "true", 4) == 0) {
    p->pos += 4;
    json_value_t *v = json_alloc(JSON_BOOL);
    v->u.boolean = 1;
    return v;
  }
  if (c == 'f' && p->pos + 5 <= p->len &&
      strncmp(p->s + p->pos, "false", 5) == 0) {
    p->pos += 5;
    json_value_t *v = json_alloc(JSON_BOOL);
    v->u.boolean = 0;
    return v;
  }
  if (c == 'n' && p->pos + 4 <= p->len &&
      strncmp(p->s + p->pos, "null", 4) == 0) {
    p->pos += 4;
    return json_alloc(JSON_NULL);
  }
  if (c == '-' || isdigit((unsigned char)c))
    return parse_number(p);
  p->pos++; /* unknown token: advance so we never spin forever on malformed
               input */
  return json_alloc(JSON_NULL);
}

json_value_t *json_parse(const char *text) {
  json_parser_t p = {.s = text, .pos = 0, .len = strlen(text)};
  return parse_value(&p);
}

void json_free(json_value_t *v) {
  if (!v)
    return;
  switch (v->type) {
  case JSON_STRING:
    free(v->u.string);
    break;
  case JSON_ARRAY:
    for (size_t i = 0; i < v->u.array.count; i++)
      json_free(v->u.array.items[i]);
    free(v->u.array.items);
    break;
  case JSON_OBJECT: {
    json_member_t *m = v->u.object;
    while (m) {
      json_member_t *next = m->next;
      free(m->key);
      json_free(m->value);
      free(m);
      m = next;
    }
    break;
  }
  default:
    break;
  }
  free(v);
}

json_value_t *json_object_get(const json_value_t *obj, const char *key) {
  if (!obj || obj->type != JSON_OBJECT)
    return NULL;
  for (json_member_t *m = obj->u.object; m; m = m->next) {
    if (strcmp(m->key, key) == 0)
      return m->value;
  }
  return NULL;
}

const char *json_get_string(const json_value_t *obj, const char *key,
                            const char *def) {
  json_value_t *v = json_object_get(obj, key);
  if (v && v->type == JSON_STRING)
    return v->u.string;
  return def;
}

int json_get_bool(const json_value_t *obj, const char *key, int def) {
  json_value_t *v = json_object_get(obj, key);
  if (v && v->type == JSON_BOOL)
    return v->u.boolean;
  return def;
}

double json_get_number(const json_value_t *obj, const char *key, double def) {
  json_value_t *v = json_object_get(obj, key);
  if (v && v->type == JSON_NUMBER)
    return v->u.number;
  return def;
}

size_t json_array_size(const json_value_t *arr) {
  if (!arr || arr->type != JSON_ARRAY)
    return 0;
  return arr->u.array.count;
}

json_value_t *json_array_get(const json_value_t *arr, size_t idx) {
  if (!arr || arr->type != JSON_ARRAY || idx >= arr->u.array.count)
    return NULL;
  return arr->u.array.items[idx];
}
