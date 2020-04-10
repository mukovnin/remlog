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

// our firmware doesn't contain libbsd (strlcpy)
char *strcpy_safe(char *dst, const char *src, size_t sz)
{
    char *ret = dst;
    if (sz) {
        while (sz && (*dst++ = *src++))
            --sz;
        if (!sz)
            dst[-1] = '\0';
    }
	return ret;
}
