/**
 * TLS Filler Library 3
 */

#include <stdint.h>

__thread uint8_t tls_filler_data3[256] __attribute__((used));

void tls_filler3_init(void) {
    tls_filler_data3[0] = 1;
    tls_filler_data3[255] = 1;
}

void* tls_filler3_get_address(void) {
    return (void*)tls_filler_data3;
}
