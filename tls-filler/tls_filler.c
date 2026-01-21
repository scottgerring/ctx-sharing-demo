/**
 * TLS Filler Library 1
 *
 * Small TLS allocation (256 bytes) that fits in glibc's static TLS surplus.
 * By loading multiple small filler libraries, we consume the surplus piece by piece.
 */

#include <stdint.h>

__thread uint8_t tls_filler_data[256] __attribute__((used));

void tls_filler_init(void) {
    tls_filler_data[0] = 1;
    tls_filler_data[255] = 1;
}

void* tls_filler_get_address(void) {
    return (void*)tls_filler_data;
}
