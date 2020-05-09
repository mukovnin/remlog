#include "logbuf.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

struct log_buffer_t {
    char *buffer;
    char *tag;
    size_t max_size, capacity, write_pos;
    ssize_t oldest, newest;
};

struct log_buffer_entry_t {
    ssize_t next;
    struct timeval time;
    char msg[];
};

#define ENTRY_OFFSET_TO_PTR(b, offset)                                         \
    ((offset) >= 0 ? (log_buffer_entry_t *)((char *)((b)->buffer) + (offset))  \
                   : NULL)

log_buffer_t *log_buffer_create(size_t max_size, size_t initial_capacity, const char *tag)
{
    if (!max_size || initial_capacity > max_size)
        return NULL;
    log_buffer_t *pimpl = (log_buffer_t *)malloc(sizeof(log_buffer_t));
    if (!pimpl)
        return NULL;
    pimpl->oldest = pimpl->newest = -1;
    pimpl->max_size               = max_size;
    pimpl->capacity               = initial_capacity;
    pimpl->write_pos              = 0;
    pimpl->tag                    = strdup(tag);
    if (!(pimpl->buffer = malloc(pimpl->capacity))) {
        free(pimpl->tag);
        free(pimpl);
        return NULL;
    }
    return pimpl;
}

void log_buffer_free(log_buffer_t *b)
{
    free(b->tag);
    free(b->buffer);
    free(b);
}

bool log_buffer_add(log_buffer_t *b, const struct timeval *t, const char *msg)
{
    log_buffer_entry_t *newest = ENTRY_OFFSET_TO_PTR(b, b->newest);
    if (newest && timercmp(t, &newest->time, <))
        return false;
    size_t msg_len     = strlen(msg) + 1,
           total_len   = sizeof(log_buffer_entry_t) + msg_len;
    if (total_len > b->max_size)
        return false;
    size_t req_size = b->write_pos + total_len;
    if (req_size > b->capacity && b->capacity < b->max_size) {
        size_t capacity = MIN(MAX(b->capacity * 2, req_size), b->max_size);
        void *buffer    = realloc(b->buffer, capacity);
        if (!buffer)
            return false;
        b->buffer   = buffer;
        b->capacity = capacity;
    }
    if (b->write_pos + total_len > b->capacity)
        b->write_pos = b->oldest = 0;
    ssize_t boundary = b->write_pos + total_len;
    while (b->oldest >= (ssize_t)b->write_pos && b->oldest < boundary)
        b->oldest = ENTRY_OFFSET_TO_PTR(b, b->oldest)->next;
    if (b->newest >= 0)
        ENTRY_OFFSET_TO_PTR(b, b->newest)->next = b->write_pos;
    log_buffer_entry_t *e = ENTRY_OFFSET_TO_PTR(b, (ssize_t)b->write_pos);
    e->next = -1;
    e->time = *t;
    memcpy(e->msg, msg, msg_len);
    b->newest = b->write_pos;
    b->write_pos += total_len;
    if (b->oldest < 0)
        b->oldest = b->newest;
    return true;
}

const char *log_buffer_tag(log_buffer_t *b)
{
    return b->tag;
}

log_buffer_entry_t *log_buffer_oldest_entry(log_buffer_t *b,
                                            const struct timeval *since)
{
    log_buffer_entry_t *p = ENTRY_OFFSET_TO_PTR(b, b->oldest);
    while (p && timercmp(&p->time, since, <))
        p = ENTRY_OFFSET_TO_PTR(b, p->next);
    return p;
}

log_buffer_entry_t *log_buffer_next_entry(log_buffer_t *b,
                                          log_buffer_entry_t *e)
{
    return ENTRY_OFFSET_TO_PTR(b, e->next);
}

const struct timeval *log_entry_timestamp(log_buffer_entry_t *e)
{
    return &e->time;
}

const char *log_entry_message(log_buffer_entry_t *e)
{
    return e->msg;
}
