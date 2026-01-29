#ifndef PROCESS_CONTEXT_H
#define PROCESS_CONTEXT_H

/**
 * Process-context publishing for simple-writer variants.
 *
 * This provides just enough process-context publishing to make the
 * context-reader work with our simple-writer binaries. It uses fixed
 * values shared across all variants for consistent testing.
 */

#include <stdint.h>

/* Fixed values for reproducible testing */
extern const uint8_t TRACE_ID[16];
extern const uint8_t SPAN_ID[8];

/* Attribute key indices */
#define METHOD_IDX 0
#define ROUTE_IDX  1
#define USER_IDX   2

/* Max record size */
#define MAX_RECORD_SIZE 512

/**
 * Publish process-context with our standard configuration.
 *
 * Creates an anonymous mmap with OTEL_CTX signature so context-reader
 * can discover our v2 configuration (max_record_size, key mappings).
 *
 * @return Pointer to the mmap region, or NULL on failure
 */
void *publish_process_context(void);

#endif /* PROCESS_CONTEXT_H */
