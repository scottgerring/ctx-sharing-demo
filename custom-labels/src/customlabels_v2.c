#include "customlabels_v2.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define BARRIER atomic_thread_fence(memory_order_seq_cst)

// Process-global max record size, set via setup()
static uint64_t g_max_record_size = 0;

__attribute__((retain))
__thread custom_labels_v2_tl_record_t *custom_labels_current_set_v2 = NULL;

void custom_labels_v2_setup(uint64_t max_record_size) {
    g_max_record_size = max_record_size;
}

uint64_t custom_labels_v2_get_max_record_size(void) {
    return g_max_record_size;
}

custom_labels_v2_tl_record_t *custom_labels_v2_record_new(void) {
    if (g_max_record_size == 0) {
        return NULL;  // setup() not called
    }

    custom_labels_v2_tl_record_t *record = calloc(1, g_max_record_size);
    if (!record) {
        return NULL;
    }
    record->valid = 0;
    record->attrs_data_size = 0;
    return record;
}

void custom_labels_v2_record_free(custom_labels_v2_tl_record_t *record) {
    free(record);
}

void custom_labels_v2_record_set_trace(
    custom_labels_v2_tl_record_t *record,
    const uint8_t trace_id[16],
    const uint8_t span_id[8]
) {
    if (!record) {
        return;
    }
    if (trace_id) {
        memcpy(record->trace_id, trace_id, 16);
    }
    if (span_id) {
        memcpy(record->span_id, span_id, 8);
    }
}

int custom_labels_v2_record_set_attr(
    custom_labels_v2_tl_record_t *record,
    uint8_t key_index,
    const void *value,
    uint8_t value_length
) {
    if (!record) {
        return -1;
    }

    if (g_max_record_size == 0) {
        return -1;  // setup() not called
    }

    // Current offset is tracked by attrs_data_size
    size_t current_offset = record->attrs_data_size;
    size_t attr_size = 2 + value_length;  // [key:1][length:1][val:length]
    size_t needed = current_offset + attr_size;
    size_t available = g_max_record_size - sizeof(custom_labels_v2_tl_record_t);

    if (needed > available) {
        return -1;  // Buffer full, no realloc
    }

    uint8_t *write_ptr = &record->attrs_data[current_offset];
    write_ptr[0] = key_index;
    write_ptr[1] = value_length;
    if (value && value_length > 0) {
        memcpy(&write_ptr[2], value, value_length);
    }

    BARRIER;
    record->attrs_data_size += attr_size;

    return 0;
}

custom_labels_v2_tl_record_t *custom_labels_v2_set_current_record(
    custom_labels_v2_tl_record_t *new_record
) {
    custom_labels_v2_tl_record_t *old_record = custom_labels_current_set_v2;
    BARRIER;
    custom_labels_current_set_v2 = new_record;
    BARRIER;
    return old_record;
}

custom_labels_v2_tl_record_t *custom_labels_v2_get_current_record(void) {
    return custom_labels_current_set_v2;
}

// Debug helper: get the address of the TLS variable itself (not its value)
void *custom_labels_v2_get_tls_address(void) {
    return (void *)&custom_labels_current_set_v2;
}
