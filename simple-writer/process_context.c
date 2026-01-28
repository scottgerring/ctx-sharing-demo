/**
 * Process-context publishing for simple-writer variants.
 *
 * The protobuf encoder here is minimal and hardcoded for our specific
 * use case. It is not a general-purpose protobuf library.
 */

#define _GNU_SOURCE
#include "process_context.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

/* Fixed values shared by all variants */
const uint8_t TRACE_ID[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

const uint8_t SPAN_ID[8] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

/* Key configuration - position in array = key index */
static const char *KEY_NAMES[] = {"method", "route", "user"};
static const size_t KEY_COUNT = 3;

/* ============================================================================
 * Minimal protobuf encoder
 * ============================================================================ */

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

static void pb_write_kv_int(pb_writer_t *w, const char *key, int64_t val) {
    pb_writer_t kv_buf = {NULL, 0, 0};
    uint8_t kv_data[256];
    kv_buf.buf = kv_data;
    kv_buf.cap = sizeof(kv_data);

    pb_write_tag(&kv_buf, 1, WIRE_TYPE_LEN);
    pb_write_string(&kv_buf, key);

    pb_writer_t any_buf = {NULL, 0, 0};
    uint8_t any_data[64];
    any_buf.buf = any_data;
    any_buf.cap = sizeof(any_data);

    pb_write_tag(&any_buf, 3, WIRE_TYPE_VARINT);
    pb_write_varint_u64(&any_buf, val);

    pb_write_tag(&kv_buf, 2, WIRE_TYPE_LEN);
    pb_write_varint_u64(&kv_buf, any_buf.pos);
    for (size_t i = 0; i < any_buf.pos; i++) {
        pb_write_byte(&kv_buf, any_buf.buf[i]);
    }

    pb_write_tag(w, 1, WIRE_TYPE_LEN);
    pb_write_varint_u64(w, kv_buf.pos);
    for (size_t i = 0; i < kv_buf.pos; i++) {
        pb_write_byte(w, kv_buf.buf[i]);
    }
}

static void pb_write_kv_str(pb_writer_t *w, const char *key, const char *val) {
    pb_writer_t kv_buf = {NULL, 0, 0};
    uint8_t kv_data[256];
    kv_buf.buf = kv_data;
    kv_buf.cap = sizeof(kv_data);

    pb_write_tag(&kv_buf, 1, WIRE_TYPE_LEN);
    pb_write_string(&kv_buf, key);

    pb_writer_t any_buf = {NULL, 0, 0};
    uint8_t any_data[128];
    any_buf.buf = any_data;
    any_buf.cap = sizeof(any_data);

    // AnyValue.string_value = field 1, wire type LEN
    pb_write_tag(&any_buf, 1, WIRE_TYPE_LEN);
    pb_write_string(&any_buf, val);

    pb_write_tag(&kv_buf, 2, WIRE_TYPE_LEN);
    pb_write_varint_u64(&kv_buf, any_buf.pos);
    for (size_t i = 0; i < any_buf.pos; i++) {
        pb_write_byte(&kv_buf, any_buf.buf[i]);
    }

    pb_write_tag(w, 1, WIRE_TYPE_LEN);
    pb_write_varint_u64(w, kv_buf.pos);
    for (size_t i = 0; i < kv_buf.pos; i++) {
        pb_write_byte(w, kv_buf.buf[i]);
    }
}

static void pb_write_kv_array(pb_writer_t *w, const char *key,
                              const char **values, size_t count) {
    // Build ArrayValue: repeated AnyValue values = field 1
    pb_writer_t array_buf = {NULL, 0, 0};
    uint8_t array_data[512];
    array_buf.buf = array_data;
    array_buf.cap = sizeof(array_data);

    for (size_t i = 0; i < count; i++) {
        pb_writer_t val_buf = {NULL, 0, 0};
        uint8_t val_data[128];
        val_buf.buf = val_data;
        val_buf.cap = sizeof(val_data);

        // AnyValue.string_value = field 1, wire type LEN
        pb_write_tag(&val_buf, 1, WIRE_TYPE_LEN);
        pb_write_string(&val_buf, values[i]);

        // ArrayValue.values = field 1, wire type LEN
        pb_write_tag(&array_buf, 1, WIRE_TYPE_LEN);
        pb_write_varint_u64(&array_buf, val_buf.pos);
        for (size_t j = 0; j < val_buf.pos; j++) {
            pb_write_byte(&array_buf, val_buf.buf[j]);
        }
    }

    // Build KeyValue
    pb_writer_t kv_buf = {NULL, 0, 0};
    uint8_t kv_data[1024];
    kv_buf.buf = kv_data;
    kv_buf.cap = sizeof(kv_data);

    pb_write_tag(&kv_buf, 1, WIRE_TYPE_LEN);
    pb_write_string(&kv_buf, key);

    // AnyValue.array_value = field 5, wire type LEN
    pb_writer_t any_buf = {NULL, 0, 0};
    uint8_t any_data[768];
    any_buf.buf = any_data;
    any_buf.cap = sizeof(any_data);

    pb_write_tag(&any_buf, 5, WIRE_TYPE_LEN);
    pb_write_varint_u64(&any_buf, array_buf.pos);
    for (size_t i = 0; i < array_buf.pos; i++) {
        pb_write_byte(&any_buf, array_buf.buf[i]);
    }

    pb_write_tag(&kv_buf, 2, WIRE_TYPE_LEN);
    pb_write_varint_u64(&kv_buf, any_buf.pos);
    for (size_t i = 0; i < any_buf.pos; i++) {
        pb_write_byte(&kv_buf, any_buf.buf[i]);
    }

    pb_write_tag(w, 1, WIRE_TYPE_LEN);
    pb_write_varint_u64(w, kv_buf.pos);
    for (size_t i = 0; i < kv_buf.pos; i++) {
        pb_write_byte(w, kv_buf.buf[i]);
    }
}

/* ============================================================================
 * Process-context header structure
 * ============================================================================ */

typedef struct {
    uint8_t signature[8];
    uint32_t version;
    uint32_t payload_size;
    uint64_t published_at_ns;
    void *payload_ptr;
} __attribute__((packed)) process_ctx_header_t;

/* ============================================================================
 * Public API
 * ============================================================================ */

void *publish_process_context(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    size_t mapping_size = page_size * 2;

    void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    if (madvise(mapping, mapping_size, MADV_DONTFORK) == -1) {
        perror("madvise");
        munmap(mapping, mapping_size);
        return NULL;
    }

    process_ctx_header_t *hdr = (process_ctx_header_t *)mapping;
    uint8_t *payload = (uint8_t *)mapping + sizeof(process_ctx_header_t);
    size_t payload_cap = mapping_size - sizeof(process_ctx_header_t);

    pb_writer_t w = {payload, 0, payload_cap};
    pb_write_kv_str(&w, "threadlocal.schema_version", "tlsdesc_v1_dev");
    pb_write_kv_int(&w, "threadlocal.max_record_size", MAX_RECORD_SIZE);
    pb_write_kv_array(&w, "threadlocal.attribute_key_map", KEY_NAMES, KEY_COUNT);

    if (w.pos >= w.cap) {
        fprintf(stderr, "ERROR: Payload buffer overflow\n");
        munmap(mapping, mapping_size);
        return NULL;
    }

    memset(hdr->signature, 0, 8);
    hdr->version = 2;
    hdr->payload_size = w.pos;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    hdr->published_at_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    hdr->payload_ptr = payload;

    __sync_synchronize();

    memcpy(hdr->signature, "OTEL_CTX", 8);

    if (mprotect(mapping, mapping_size, PROT_READ) == -1) {
        perror("mprotect");
        munmap(mapping, mapping_size);
        return NULL;
    }

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, mapping, mapping_size, "OTEL_CTX");

    printf("Published process-context at %p (payload size: %zu)\n", mapping, w.pos);
    return mapping;
}
