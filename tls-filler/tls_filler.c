/**
 * TLS Filler Library (Parameterized)
 *
 * Small TLS allocation (256 bytes) that fits in glibc's static TLS surplus.
 * By loading multiple small filler libraries, we consume the surplus piece by piece.
 *
 * Build with -DTLS_FILLER_SUFFIX=N to create variants (tls_filler_data1, tls_filler_data2, etc.)
 * Without the define, creates the base variant (tls_filler_data).
 */

#include <stdint.h>

/* Macro concatenation helpers */
#define CONCAT(a, b) a##b
#define CONCAT2(a, b) CONCAT(a, b)

/* Define the suffix (default empty if not specified) */
#ifdef TLS_FILLER_SUFFIX
  #define DATA_NAME CONCAT2(tls_filler_data, TLS_FILLER_SUFFIX)
  #define INIT_NAME CONCAT2(tls_filler, CONCAT2(TLS_FILLER_SUFFIX, _init))
  #define GET_ADDR_NAME CONCAT2(tls_filler, CONCAT2(TLS_FILLER_SUFFIX, _get_address))
#else
  #define DATA_NAME tls_filler_data
  #define INIT_NAME tls_filler_init
  #define GET_ADDR_NAME tls_filler_get_address
#endif

__thread uint8_t DATA_NAME[256] __attribute__((used));

void INIT_NAME(void) {
    DATA_NAME[0] = 1;
    DATA_NAME[255] = 1;
}

void* GET_ADDR_NAME(void) {
    return (void*)DATA_NAME;
}
