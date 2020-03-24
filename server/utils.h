#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

uint64_t current_time_us();

#endif
