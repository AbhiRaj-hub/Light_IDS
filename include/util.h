#ifndef IDS_UTIL_H
#define IDS_UTIL_H

#include <cstddef>
#include <stddef.h>

// Converts special characters into valid JSON escape sequences,
// Strips unprintable characters, prevents buffer overflow
void ids_json_escape(const char *in, char *out, size_t outsize);

// Converts binary or raw byte data into an ASCII-safe Base64 string
void ids_base64_encode(const unsigned char *data, size_t len, char *out,
                       size_t outsize);

#endif
