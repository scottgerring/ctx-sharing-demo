# TLS Filler Library
# Consumes static TLS space to force subsequent dlopen'd libraries into DTV
#
# Uses a single parameterized source file (tls_filler.c) with -DTLS_FILLER_SUFFIX
# to generate multiple variants.

# Detect architecture and set TLS dialect
ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
    TLS_DIALECT = desc
else ifeq ($(ARCH),arm64)
    TLS_DIALECT = desc
else ifeq ($(ARCH),x86_64)
    TLS_DIALECT = gnu2
else
    $(error only aarch64/arm64 and x86-64 are supported)
endif

CFLAGS = -Wall -Wextra -std=c11 -fPIC -ftls-model=global-dynamic -mtls-dialect=$(TLS_DIALECT)

.PHONY: all clean

all: libtlsfiller.so libtlsfiller2.so libtlsfiller3.so

# Base variant (no suffix)
libtlsfiller.so: tls_filler.c
	gcc $(CFLAGS) -shared -o $@ $<

# Variant 2
libtlsfiller2.so: tls_filler.c
	gcc $(CFLAGS) -DTLS_FILLER_SUFFIX=2 -shared -o $@ $<

# Variant 3
libtlsfiller3.so: tls_filler.c
	gcc $(CFLAGS) -DTLS_FILLER_SUFFIX=3 -shared -o $@ $<

clean:
	rm -f libtlsfiller.so libtlsfiller2.so libtlsfiller3.so
