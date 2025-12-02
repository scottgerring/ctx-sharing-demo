/**
This file contains the **process scoped** data needed to support
the TLS system. This includes attribute mapping tables and supported
TL version. It is foreseeable this ends up in the process context sharing
specification and not here!
**/

#ifndef CUSTOMLABELS_V2_PROCESS_H
#define CUSTOMLABELS_V2_PROCESS_H

#include <stddef.h>
#include <stdint.h>

// Key table: immutable registry of key names. Keys are then referenced by uint8
// index into this table in the TL context data, keeping the actual context update
// payload lean.
//
// Keys are packed with variable length - each key is stored as [length:1][value:length].
// To find a key by index, iterate from the start.
typedef struct {
    // The number of bytes in the key_data array
    uint32_t key_data_size;

    // Key data array. Each key entry is: [length:1][value:length]
    // Keys are referenced by array index (0, 1, 2, ...) and must be found by iteration.
    uint8_t key_data[];
} custom_labels_v2_key_table_t;

//
// Reference Data: process-wide immutable configuration
// This is optimally set _globally_ in the process once at startup
// and contains the information we need to decode the TL updates.
// It would be great to include this as part of the process context proposal.
//
typedef struct {
    // The version of our schema. For now we are using 1
    uint8_t schema_version;

    // Explicitly padding to 8-byte boundary for key_table pointer
    uint8_t _reserved[7];

    // Table of key names
    const custom_labels_v2_key_table_t *key_table;

    // The maximum size of a TL context record. The implementation must make
    // sure to malloc() each record to cover this size so the reader is free
    // to read without first having to parse the record.
    uint64_t max_record_size;
} custom_labels_v2_ref_data_t;

extern const uint32_t custom_labels_abi_version_v2;
extern __thread const custom_labels_v2_ref_data_t *custom_labels_current_ref_v2;

// Allocate a new key table with space for initial_buffer_size bytes of key data.
custom_labels_v2_key_table_t *custom_labels_v2_key_table_new(size_t initial_buffer_size);

// Register a key name; returns its index or -1 on error.
int custom_labels_v2_key_table_register(
    custom_labels_v2_key_table_t **table,
    const char *key_name
);

// Free a key table.
void custom_labels_v2_key_table_free(custom_labels_v2_key_table_t *table);

// Allocate new ref data. This should only be called once per process!
custom_labels_v2_ref_data_t *custom_labels_v2_ref_data_new(
    const custom_labels_v2_key_table_t *key_table,
    uint64_t max_record_size
);

// Free the ref data
void custom_labels_v2_ref_data_free(custom_labels_v2_ref_data_t *ref);

// Get the current thread's ref data pointer

// NOTE: We really want this to be process wide, and not off of the TL. But to keep
// things simple and self contained, we set the ref_data TL on each thread to point
// to the one global instance. For now.
const custom_labels_v2_ref_data_t *custom_labels_v2_get_ref_data(void);

// Set the current thread's ref data pointer
void custom_labels_v2_set_ref_data(const custom_labels_v2_ref_data_t *ref);

#endif /* CUSTOMLABELS_V2_PROCESS_H */
