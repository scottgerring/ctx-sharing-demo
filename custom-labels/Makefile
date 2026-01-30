CC = gcc
TARGET_SO = libcustomlabels.so
TARGET_MUSL_SO = libcustomlabels-musl.so
TARGET_A = libcustomlabels.a
SRCS = src/customlabels.c src/customlabels_v2.c

ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
    TLS_DIALECT = desc
else ifeq ($(ARCH),x86_64)
    TLS_DIALECT = gnu2
else
    $(error only aarch64 and x86-64 are supported)
endif

# Common flags for both static and dynamic libraries
COMMON_CFLAGS = $(CFLAGS) -ftls-model=global-dynamic -mtls-dialect=$(TLS_DIALECT) -fPIC

# Shared library target (glibc)
$(TARGET_SO): $(SRCS)
	$(CC) $(COMMON_CFLAGS) -shared -o $(TARGET_SO) $(SRCS)

# Shared library target (musl)
# musl provides dlopen/pthread in libc directly, no extra link flags needed
$(TARGET_MUSL_SO): $(SRCS)
	musl-gcc $(COMMON_CFLAGS) -shared -o $(TARGET_MUSL_SO) $(SRCS)

# Static library target
OBJS = $(SRCS:.c=.o)

%.o: %.c
	$(CC) $(COMMON_CFLAGS) -c -o $@ $<

$(TARGET_A): $(OBJS)
	ar rcs $@ $^

all: $(TARGET_SO) $(TARGET_A)

clean:
	rm -f $(TARGET_SO) $(TARGET_MUSL_SO) $(TARGET_A) $(OBJS)
