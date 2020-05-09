#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

char *strcpy_safe(char *dst, const char *src, size_t sz);
bool matches_mask(const char *str, const char *mask);

#endif
