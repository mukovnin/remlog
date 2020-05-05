#ifndef LOGBUF_H
#define LOGBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct log_buffer_t log_buffer_t;
typedef struct log_buffer_entry_t log_buffer_entry_t;

log_buffer_t *log_buffer_create(size_t max_size, size_t initial_capacity, const char *tag);
void log_buffer_free(log_buffer_t *b);
bool log_buffer_add(log_buffer_t *b, uint64_t t, const char *msg);
const char *log_buffer_tag(log_buffer_t *b);

log_buffer_entry_t *log_buffer_oldest_entry(log_buffer_t *b,
                                            uint64_t since);
log_buffer_entry_t *log_buffer_next_entry(log_buffer_t *b,
                                          log_buffer_entry_t *e);
uint64_t log_entry_timestamp(log_buffer_entry_t *e);
const char *log_entry_message(log_buffer_entry_t *e);

#endif
