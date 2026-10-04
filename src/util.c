#include "util.h"
#include <string.h>

void ids_json_escape(const char *in, char *out, size_t outsize) {
  size_t oi = 0;
  if (!in) {
    if (outsize)
      out[0] = '\0';
    return;
  }
  for (size_t i = 0; in[i] != '\0' && oi + 2 < outsize; i++) {
    unsigned char c = (unsigned char)in[i];
    switch (c) {
    case '"':
      out[oi++] = '\\';
      out[oi++] = '"';
      break;
    case '\\':
      out[oi++] = '\\';
      out[oi++] = '\\';
      break;
    case '\n':
      out[oi++] = '\\';
      out[oi++] = 'n';
      break;
    case '\r':
      out[oi++] = '\\';
      out[oi++] = 'r';
      break;
    case '\t':
      out[oi++] = '\\';
      out[oi++] = 't';
      break;
    default:
      if (c < 0x20) { /* drop other control chars */
      } else if (oi + 1 < outsize)
        out[oi++] = (char)c;
    }
  }
  out[oi] = '\0';
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void ids_base64_encode(const unsigned char *data, size_t len, char *out,
                       size_t outsize) {
  size_t oi = 0;
  for (size_t i = 0; i < len; i += 3) {
    unsigned int chunk = ((unsigned int)data[i]) << 16;
    int have2 = (i + 1 < len);
    int have3 = (i + 2 < len);
    if (have2)
      chunk |= ((unsigned int)data[i + 1]) << 8;
    if (have3)
      chunk |= data[i + 2];

    char c0 = b64_table[(chunk >> 18) & 0x3F];
    char c1 = b64_table[(chunk >> 12) & 0x3F];
    char c2 = have2 ? b64_table[(chunk >> 6) & 0x3F] : '=';
    char c3 = have3 ? b64_table[chunk & 0x3F] : '=';

    if (oi + 4 < outsize) {
      out[oi++] = c0;
      out[oi++] = c1;
      out[oi++] = c2;
      out[oi++] = c3;
    } else
      break;
  }
  out[oi] = '\0';
}
