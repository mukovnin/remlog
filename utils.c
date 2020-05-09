#include "utils.h"

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
