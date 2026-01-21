/**
 * TLS Filler Library 2
 */

#include <stdint.h>

__thread uint8_t tls_filler_data2[256] __attribute__((used));

void tls_filler2_init(void) {
    tls_filler_data2[0] = 1;
    tls_filler_data2[255] = 1;
}

void* tls_filler2_get_address(void) {
    return (void*)tls_filler_data2;
}
