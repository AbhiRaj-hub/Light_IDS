#ifndef IDS_JSON_H
#define IDS_JSON_H

#include <stddef.h>

typedef enum {
  JSON_NULL,
  JSON_BOOL,
  JSON_NUMBER,
  JSON_STRING,
  JSON_ARRAY,
  JSON_OBJECT
} json_type_t;

typedef struct json_value
    json_value_t; // Fixed Bug ~json_value_t~ not ~json_type_t~

typedef struct json_member {
  char *key;
  json_type_t *value;
  struct json_member *next;
} json_member_t;

struct json_value {
  json_type_t type;
  union {
    int boolean;
    double number;
    char *string;
    struct {
      struct json_value **items;
      size_t count;
    } array;
    json_member_t *object;
  } u;
};

// Minimal Json Parser, no need of external dependencies

json_value_t *json_parse(const char *text);
void json_free(json_value_t *v);

json_value_t *json_object_get(const json_value_t *obj, const char *key);
const char *json_get_string(const json_value_t *obj, const char *key,
                            const char *def);
int json_get_bool(const json_value_t *obj, const char *key, int def);
double json_get_number(const json_value_t *obj, const char *key, double def);

size_t json_array_size(const json_value_t *arr);
json_value_t *json_array_get(const json_value_t *arr, size_t idx);

#endif
