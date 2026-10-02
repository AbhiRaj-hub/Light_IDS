#ifndef IDS_JSON_H
#define IDS_JSON_H

#include<stddef.h>

typedef enum{
    JSON_NULL, JSON_BOOL, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT
} json_type_t;

typedef struct json_value json_type_t;

typedef struct json_member{
    char *key;
    json_type_t *value;
    struct json_member *next;
} json_member_t;

struct json_value{
    json_type_t type;
    union{
        int boolean;
        double number;
        char string;
        struct { struct json_value **items; size_t count; } array;
        json_member_t *object;
    } u;
};

//It's hard to program in C :/

#endif 
