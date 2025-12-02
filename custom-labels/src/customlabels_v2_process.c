#include "customlabels_v2_process.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define BARRIER atomic_thread_fence(memory_order_seq_cst)

#define KEY_TABLE_HEADER_SIZE sizeof(uint32_t)  // key_data_size
#define SCHEMA_VERSION_V2 1

__attribute__((retain))
const uint32_t custom_labels_abi_version_v2 = 1;

__attribute__((retain))
__thread const custom_labels_v2_ref_data_t *custom_labels_current_ref_v2 = NULL;

// Track allocated buffer capacity (stored just before the table in memory)
typedef struct {
    size_t capacity;  // Total allocated bytes for key_data
    custom_labels_v2_key_table_t table;
} key_table_with_capacity_t;

static inline key_table_with_capacity_t *get_table_container(custom_labels_v2_key_table_t *table) {
    return (key_table_with_capacity_t *)((char *)table - offsetof(key_table_with_capacity_t, table));
}

custom_labels_v2_key_table_t *custom_labels_v2_key_table_new(size_t initial_buffer_size) {
    if (initial_buffer_size == 0) {
        initial_buffer_size = 256;  // Default buffer size
    }
    size_t alloc_size = sizeof(key_table_with_capacity_t) + initial_buffer_size;
    key_table_with_capacity_t *container = calloc(1, alloc_size);
    if (!container) {
        return NULL;
    }
    container->capacity = initial_buffer_size;
    container->table.key_data_size = 0;
    return &container->table;
}

// Count the number of keys in a table by iterating through
static int count_keys(const custom_labels_v2_key_table_t *table) {
    int count = 0;
    uint32_t offset = 0;
    while (offset < table->key_data_size) {
        uint8_t len = table->key_data[offset];
        offset += 1 + len;
        count++;
    }
    return count;
}

int custom_labels_v2_key_table_register(
    custom_labels_v2_key_table_t **table_ptr,
    const char *key_name
) {
    if (!table_ptr || !*table_ptr || !key_name) {
        return -1;
    }

    custom_labels_v2_key_table_t *table = *table_ptr;
    size_t key_len = strlen(key_name);

    if (key_len > 255) {
        return -1;  // Key length must fit in uint8
    }

    // Calculate space needed for new entry: length(1) + value(key_len)
    size_t entry_size = 1 + key_len;
    size_t new_data_size = table->key_data_size + entry_size;

    // Check if we need to grow the buffer
    key_table_with_capacity_t *container = get_table_container(table);
    if (new_data_size > container->capacity) {
        // Double the capacity (or more if needed)
        size_t new_capacity = container->capacity * 2;
        if (new_capacity < new_data_size) {
            new_capacity = new_data_size;
        }
        size_t new_alloc = sizeof(key_table_with_capacity_t) + new_capacity;
        key_table_with_capacity_t *new_container = realloc(container, new_alloc);
        if (!new_container) {
            return -1;
        }
        new_container->capacity = new_capacity;
        container = new_container;
        table = &container->table;
        *table_ptr = table;
    }

    // Count existing keys to get the index
    int index = count_keys(table);
    if (index >= 256) {
        return -1;  // Too many keys
    }

    // Append the new key at the end
    uint8_t *entry = table->key_data + table->key_data_size;
    entry[0] = (uint8_t)key_len;
    memcpy(&entry[1], key_name, key_len);

    BARRIER;

    table->key_data_size = (uint32_t)new_data_size;

    return index;
}

void custom_labels_v2_key_table_free(custom_labels_v2_key_table_t *table) {
    if (table) {
        // Free the container that holds the table
        key_table_with_capacity_t *container = get_table_container(table);
        free(container);
    }
}

custom_labels_v2_ref_data_t *custom_labels_v2_ref_data_new(
    const custom_labels_v2_key_table_t *key_table,
    uint64_t max_record_size
) {
    custom_labels_v2_ref_data_t *ref = calloc(1, sizeof(custom_labels_v2_ref_data_t));
    if (!ref) {
        return NULL;
    }
    ref->schema_version = SCHEMA_VERSION_V2;
    ref->key_table = key_table;
    ref->max_record_size = max_record_size;
    return ref;
}

void custom_labels_v2_ref_data_free(custom_labels_v2_ref_data_t *ref) {
    free(ref);
}

const custom_labels_v2_ref_data_t *custom_labels_v2_get_ref_data(void) {
    return custom_labels_current_ref_v2;
}

void custom_labels_v2_set_ref_data(const custom_labels_v2_ref_data_t *ref) {
    custom_labels_current_ref_v2 = ref;
}
