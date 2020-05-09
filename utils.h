#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

char *strcpy_safe(char *dst, const char *src, size_t sz);

#endif
