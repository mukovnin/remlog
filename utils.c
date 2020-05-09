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

bool matches_mask(const char *str, const char *mask)
{
    if (!(*str) && !(*mask))
        return true;
    if (*mask == '*' && *(mask + 1) && !(*str))
        return false;
    if (*mask == '?' || *mask == *str)
        return matches_mask(str + 1, mask + 1);
    if (*mask == '*')
        return matches_mask(str, mask + 1) || matches_mask(str + 1, mask);
    return false;
}
