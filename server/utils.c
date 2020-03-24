#include "utils.h"
#include <stddef.h>
#include <sys/time.h>

uint64_t current_time_us()
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0)
        return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
    else
        return 0;
}
