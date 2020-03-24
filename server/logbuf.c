#include "logbuf.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

struct log_buffer_t {
    char *buffer;
    size_t max_size, capacity, write_pos;
    ssize_t oldest, newest;
};

struct log_buffer_entry_t {
    ssize_t next;
    uint64_t time;
    char msg[];
};

#define ENTRY_OFFSET_TO_PTR(b, offset)                                         \
    ((offset) >= 0 ? (log_buffer_entry_t *)((char *)((b)->buffer) + (offset))  \
                   : NULL)

log_buffer_t *log_buffer_create(size_t max_size, size_t initial_capacity)
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
    if (!(pimpl->buffer = malloc(pimpl->capacity))) {
        free(pimpl);
        return NULL;
    }
    return pimpl;
}

void log_buffer_free(log_buffer_t *b)
{
    free(b->buffer);
    free(b);
}

bool log_buffer_add(log_buffer_t *b, const char *msg)
{
    uint64_t timestamp = current_time_us();
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
    e->time = timestamp;
    memcpy(e->msg, msg, msg_len);
    b->newest = b->write_pos;
    b->write_pos += total_len;
    if (b->oldest < 0)
        b->oldest = b->newest;
    return true;
}

const log_buffer_entry_t *log_buffer_oldest_entry(log_buffer_t *b,
                                                  uint64_t since)
{
    log_buffer_entry_t *p = ENTRY_OFFSET_TO_PTR(b, b->oldest);
    while (p && p->time < since)
        p = ENTRY_OFFSET_TO_PTR(b, p->next);
    return p;
}

const log_buffer_entry_t *log_buffer_next_entry(log_buffer_t *b,
                                                const log_buffer_entry_t *e)
{
    return ENTRY_OFFSET_TO_PTR(b, e->next);
}

uint64_t log_entry_timestamp(const log_buffer_entry_t *e)
{
    return e->time;
}

const char *log_entry_message(const log_buffer_entry_t *e)
{
    return e->msg;
}
