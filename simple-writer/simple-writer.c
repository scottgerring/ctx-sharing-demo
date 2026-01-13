#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include "customlabels_v2.h"

// Fixed test values for reproducible testing
static const uint8_t TRACE_ID[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t SPAN_ID[8] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

static const uint8_t ROOT_SPAN_ID[8] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11
};

// Key indices matching context-writer pattern
#define METHOD_IDX 0
#define ROUTE_IDX  1
#define USER_IDX   2

static volatile sig_atomic_t running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

// ============================================================================
// Process-context publishing (minimal protobuf encoder)
// ============================================================================

#define WIRE_TYPE_VARINT 0
#define WIRE_TYPE_LEN 2

typedef struct {
    uint8_t *buf;
    size_t pos;
    size_t cap;
} pb_writer_t;

static void pb_write_byte(pb_writer_t *w, uint8_t b) {
    if (w->pos < w->cap) {
        w->buf[w->pos++] = b;
    }
}

static void pb_write_varint_u64(pb_writer_t *w, uint64_t v) {
    while (v >= 0x80) {
        pb_write_byte(w, (uint8_t)(v | 0x80));
        v >>= 7;
    }
    pb_write_byte(w, (uint8_t)v);
}

static void pb_write_tag(pb_writer_t *w, uint8_t field, uint8_t wire_type) {
    pb_write_byte(w, (field << 3) | wire_type);
}

static void pb_write_string(pb_writer_t *w, const char *s) {
    size_t len = strlen(s);
    pb_write_varint_u64(w, len);
    for (size_t i = 0; i < len; i++) {
        pb_write_byte(w, s[i]);
    }
}

// Write KeyValue(key=string, value=Int64)
static void pb_write_kv_int(pb_writer_t *w, const char *key, int64_t val) {
    pb_writer_t kv_buf = {NULL, 0, 0};
    uint8_t kv_data[256];
    kv_buf.buf = kv_data;
    kv_buf.cap = sizeof(kv_data);

    // KeyValue.key = field 1
    pb_write_tag(&kv_buf, 1, WIRE_TYPE_LEN);
    pb_write_string(&kv_buf, key);

    // KeyValue.value = field 2 (AnyValue message)
    pb_writer_t any_buf = {NULL, 0, 0};
    uint8_t any_data[64];
    any_buf.buf = any_data;
    any_buf.cap = sizeof(any_data);

    // AnyValue.int_value = field 3
    pb_write_tag(&any_buf, 3, WIRE_TYPE_VARINT);
    pb_write_varint_u64(&any_buf, val);

    pb_write_tag(&kv_buf, 2, WIRE_TYPE_LEN);
    pb_write_varint_u64(&kv_buf, any_buf.pos);
    for (size_t i = 0; i < any_buf.pos; i++) {
        pb_write_byte(&kv_buf, any_buf.buf[i]);
    }

    // Resource.attributes = field 1
    pb_write_tag(w, 1, WIRE_TYPE_LEN);
    pb_write_varint_u64(w, kv_buf.pos);
    for (size_t i = 0; i < kv_buf.pos; i++) {
        pb_write_byte(w, kv_buf.buf[i]);
    }
}

// Write KeyValue(key=string, value=KvList)
static void pb_write_kv_kvlist(pb_writer_t *w, const char *key,
                               const uint8_t *indices, const char **names, size_t count) {
    // Build KvList message
    pb_writer_t kvlist_buf = {NULL, 0, 0};
    uint8_t kvlist_data[512];
    kvlist_buf.buf = kvlist_data;
    kvlist_buf.cap = sizeof(kvlist_data);

    for (size_t i = 0; i < count; i++) {
        // Build inner KeyValue(index_str, name)
        pb_writer_t inner_kv_buf = {NULL, 0, 0};
        uint8_t inner_kv_data[128];
        inner_kv_buf.buf = inner_kv_data;
        inner_kv_buf.cap = sizeof(inner_kv_data);

        char index_str[8];
        snprintf(index_str, sizeof(index_str), "%u", indices[i]);

        // KeyValue.key = field 1
        pb_write_tag(&inner_kv_buf, 1, WIRE_TYPE_LEN);
        pb_write_string(&inner_kv_buf, index_str);

        // KeyValue.value = field 2 (AnyValue with string)
        pb_writer_t inner_any_buf = {NULL, 0, 0};
        uint8_t inner_any_data[64];
        inner_any_buf.buf = inner_any_data;
        inner_any_buf.cap = sizeof(inner_any_data);

        pb_write_tag(&inner_any_buf, 1, WIRE_TYPE_LEN);  // AnyValue.string_value
        pb_write_string(&inner_any_buf, names[i]);

        pb_write_tag(&inner_kv_buf, 2, WIRE_TYPE_LEN);
        pb_write_varint_u64(&inner_kv_buf, inner_any_buf.pos);
        for (size_t j = 0; j < inner_any_buf.pos; j++) {
            pb_write_byte(&inner_kv_buf, inner_any_buf.buf[j]);
        }

        // KeyValueList.values = field 1
        pb_write_tag(&kvlist_buf, 1, WIRE_TYPE_LEN);
        pb_write_varint_u64(&kvlist_buf, inner_kv_buf.pos);
        for (size_t j = 0; j < inner_kv_buf.pos; j++) {
            pb_write_byte(&kvlist_buf, inner_kv_buf.buf[j]);
        }
    }

    // Build outer KeyValue(key, KvList)
    pb_writer_t kv_buf = {NULL, 0, 0};
    uint8_t kv_data[1024];
    kv_buf.buf = kv_data;
    kv_buf.cap = sizeof(kv_data);

    pb_write_tag(&kv_buf, 1, WIRE_TYPE_LEN);
    pb_write_string(&kv_buf, key);

    // AnyValue.kvlist_value = field 6
    pb_writer_t any_buf = {NULL, 0, 0};
    uint8_t any_data[768];
    any_buf.buf = any_data;
    any_buf.cap = sizeof(any_data);

    pb_write_tag(&any_buf, 6, WIRE_TYPE_LEN);
    pb_write_varint_u64(&any_buf, kvlist_buf.pos);
    for (size_t i = 0; i < kvlist_buf.pos; i++) {
        pb_write_byte(&any_buf, kvlist_buf.buf[i]);
    }

    pb_write_tag(&kv_buf, 2, WIRE_TYPE_LEN);
    pb_write_varint_u64(&kv_buf, any_buf.pos);
    for (size_t i = 0; i < any_buf.pos; i++) {
        pb_write_byte(&kv_buf, any_buf.buf[i]);
    }

    // Resource.attributes = field 1
    pb_write_tag(w, 1, WIRE_TYPE_LEN);
    pb_write_varint_u64(w, kv_buf.pos);
    for (size_t i = 0; i < kv_buf.pos; i++) {
        pb_write_byte(w, kv_buf.buf[i]);
    }
}

typedef struct {
    uint8_t signature[8];
    uint32_t version;
    uint32_t payload_size;
    uint64_t published_at_ns;
    void *payload_ptr;
} __attribute__((packed)) process_ctx_header_t;

static void *publish_process_context(const uint8_t *key_indices, const char **key_names,
                                     size_t key_count, uint64_t max_record_size) {
    // Create anonymous mapping (2 pages)
    long page_size = sysconf(_SC_PAGESIZE);
    size_t mapping_size = page_size * 2;

    void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    // Set MADV_DONTFORK
    if (madvise(mapping, mapping_size, MADV_DONTFORK) == -1) {
        perror("madvise");
        munmap(mapping, mapping_size);
        return NULL;
    }

    // Payload goes after header in the mapping
    process_ctx_header_t *hdr = (process_ctx_header_t *)mapping;
    uint8_t *payload = (uint8_t *)mapping + sizeof(process_ctx_header_t);
    size_t payload_cap = mapping_size - sizeof(process_ctx_header_t);

    // Encode payload directly into mapping
    pb_writer_t w = {payload, 0, payload_cap};
    pb_write_kv_int(&w, "threadlocal.schema_version", 1);
    pb_write_kv_int(&w, "threadlocal.max_record_size", max_record_size);
    pb_write_kv_kvlist(&w, "threadlocal.attribute_key_map", key_indices, key_names, key_count);

    if (w.pos >= w.cap) {
        fprintf(stderr, "ERROR: Payload buffer overflow\n");
        munmap(mapping, mapping_size);
        return NULL;
    }

    // Write header
    memset(hdr->signature, 0, 8);  // Set signature last
    hdr->version = 2;
    hdr->payload_size = w.pos;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    hdr->published_at_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    hdr->payload_ptr = payload;

    __sync_synchronize();  // Memory barrier

    memcpy(hdr->signature, "OTEL_CTX", 8);

    // Make read-only
    if (mprotect(mapping, mapping_size, PROT_READ) == -1) {
        perror("mprotect");
        munmap(mapping, mapping_size);
        return NULL;
    }

    // Try to name it (optional, may fail on older kernels)
    #ifndef PR_SET_VMA
    #define PR_SET_VMA 0x53564d41
    #define PR_SET_VMA_ANON_NAME 0
    #endif

    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, mapping, mapping_size, "OTEL_CTX");

    printf("Published process-context at %p (payload size: %zu)\n", mapping, w.pos);
    return mapping;
}

int main(void) {
    int ret = 0;

    // Step 1: Publish process-context with key table
    const uint64_t max_record_size = 512;
    const uint8_t key_indices[] = {METHOD_IDX, ROUTE_IDX, USER_IDX};
    const char *key_names[] = {"method", "route", "user"};

    void *process_ctx_mapping = publish_process_context(
        key_indices, key_names, 3, max_record_size);

    if (!process_ctx_mapping) {
        fprintf(stderr, "WARNING: Failed to publish process-context (reader may not work)\n");
    }

    // Step 2: Initialize the v2 context system
    custom_labels_v2_setup(max_record_size);

    printf("Initialized custom_labels_v2 with max_record_size=%lu\n", max_record_size);

    // Step 3: Allocate a new record
    custom_labels_v2_tl_record_t *record = custom_labels_v2_record_new();
    if (!record) {
        fprintf(stderr, "ERROR: Failed to allocate record\n");
        return 1;
    }

    // Step 4: Set trace context
    custom_labels_v2_record_set_trace(record, TRACE_ID, SPAN_ID, ROOT_SPAN_ID);

    // Step 5: Add attributes
    const char *method = "GET";
    const char *route = "/api/test";
    const char *user = "simple-writer";

    if (custom_labels_v2_record_set_attr(record, METHOD_IDX, method, strlen(method)) != 0) {
        fprintf(stderr, "ERROR: Failed to set method attribute\n");
        ret = 1;
        goto cleanup;
    }

    if (custom_labels_v2_record_set_attr(record, ROUTE_IDX, route, strlen(route)) != 0) {
        fprintf(stderr, "ERROR: Failed to set route attribute\n");
        ret = 1;
        goto cleanup;
    }

    if (custom_labels_v2_record_set_attr(record, USER_IDX, user, strlen(user)) != 0) {
        fprintf(stderr, "ERROR: Failed to set user attribute\n");
        ret = 1;
        goto cleanup;
    }

    // Step 6: Mark record as valid and attach to current thread
    record->valid = 1;
    custom_labels_v2_set_current_record(record);

    printf("Attached context to thread. TLS address: %p\n",
           custom_labels_v2_get_tls_address());
    printf("Simple writer running. Press Ctrl+C to exit.\n");

    // Step 7: Install signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    // Step 8: Wait for signal
    while (running) {
        pause();
    }

    printf("\nShutting down...\n");

    // Step 9: Cleanup - detach record
    custom_labels_v2_set_current_record(NULL);

cleanup:
    custom_labels_v2_record_free(record);
    printf("Exited cleanly\n");
    return ret;
}
