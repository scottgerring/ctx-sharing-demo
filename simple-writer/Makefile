# Detect architecture and set TLS dialect
ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
    TLS_DIALECT = desc
else ifeq ($(ARCH),x86_64)
    TLS_DIALECT = gnu2
else
    $(error only aarch64 and x86-64 are supported)
endif

# Common compiler flags
COMMON_CFLAGS = -Wall -Wextra -std=c11 -I../custom-labels/src
COMMON_TLS_FLAGS = -ftls-model=global-dynamic -mtls-dialect=$(TLS_DIALECT)

# Export TLS symbols for context-reader access
EXPORT_SYMBOLS = -Wl,--export-dynamic-symbol=custom_labels_abi_version \
                 -Wl,--export-dynamic-symbol=custom_labels_current_set_v2

# Build directory
BUILD_DIR = build

# Source files
MAIN_SRC = simple-writer.c
DLOPEN_SRC = simple-writer-dlopen.c
EXHAUST_TLS_SRC = simple-writer-exhaust-static-tls.c
PROCESS_CTX_SRC = process_context.c

# All targets
TARGETS = simple-writer-static-musl simple-writer-static-glibc \
          simple-writer-dynamic-glibc simple-writer-dynamic-musl \
          simple-writer-dlopen-glibc simple-writer-dlopen-musl \
          simple-writer-exhaust-static-tls

.PHONY: all clean $(TARGETS)

all: $(BUILD_DIR) $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile process_context.o for each toolchain
$(BUILD_DIR)/process_context-musl.o: $(PROCESS_CTX_SRC) | $(BUILD_DIR)
	musl-gcc $(COMMON_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/process_context-glibc.o: $(PROCESS_CTX_SRC) | $(BUILD_DIR)
	gcc $(COMMON_CFLAGS) -c -o $@ $<

# Variant 1: Static labels + musl (fully static binary)
simple-writer-static-musl: $(BUILD_DIR)/process_context-musl.o
	musl-gcc $(COMMON_CFLAGS) $(COMMON_TLS_FLAGS) \
		-static \
		-o $(BUILD_DIR)/$@ $(MAIN_SRC) $(BUILD_DIR)/process_context-musl.o \
		../custom-labels/libcustomlabels.a \
		$(EXPORT_SYMBOLS)

# Variant 2: Static labels + glibc (dynamically linked glibc, static custom-labels)
simple-writer-static-glibc: $(BUILD_DIR)/process_context-glibc.o
	gcc $(COMMON_CFLAGS) $(COMMON_TLS_FLAGS) \
		-o $(BUILD_DIR)/$@ $(MAIN_SRC) $(BUILD_DIR)/process_context-glibc.o \
		../custom-labels/libcustomlabels.a \
		$(EXPORT_SYMBOLS)

# Variant 3: Dynamic labels + glibc (fully dynamic)
simple-writer-dynamic-glibc: $(BUILD_DIR)/process_context-glibc.o
	gcc $(COMMON_CFLAGS) $(COMMON_TLS_FLAGS) \
		-o $(BUILD_DIR)/$@ $(MAIN_SRC) $(BUILD_DIR)/process_context-glibc.o \
		-L../custom-labels -lcustomlabels \
		-Wl,-rpath,'$$ORIGIN/../../custom-labels' \
		$(EXPORT_SYMBOLS)

# Variant 3b: Dynamic labels + musl
# musl has supported aarch64 since v1.1.7 (March 2015) and TLSDESC on
# i386/x86_64 since v1.1.3 (June 2014).
simple-writer-dynamic-musl: $(BUILD_DIR)/process_context-musl.o
	musl-gcc $(COMMON_CFLAGS) $(COMMON_TLS_FLAGS) \
		-o $(BUILD_DIR)/$@ $(MAIN_SRC) $(BUILD_DIR)/process_context-musl.o \
		-L../custom-labels -lcustomlabels-musl \
		-Wl,-rpath,'$$ORIGIN/../../custom-labels' \
		$(EXPORT_SYMBOLS)

# Variant 4: dlopen + glibc (load library at runtime with dlopen)
simple-writer-dlopen-glibc: $(BUILD_DIR)/process_context-glibc.o
	gcc $(COMMON_CFLAGS) $(COMMON_TLS_FLAGS) \
		-o $(BUILD_DIR)/$@ $(DLOPEN_SRC) $(BUILD_DIR)/process_context-glibc.o \
		-ldl -lpthread

# Variant 5: dlopen + musl (load library at runtime with dlopen under musl)
# musl provides dlopen/pthread in libc directly, no need for -ldl -lpthread
simple-writer-dlopen-musl: $(BUILD_DIR)/process_context-musl.o
	musl-gcc $(COMMON_CFLAGS) $(COMMON_TLS_FLAGS) \
		-o $(BUILD_DIR)/$@ $(DLOPEN_SRC) $(BUILD_DIR)/process_context-musl.o

# Variant 6: exhaust-static-tls (dlopen filler first to force DTV usage)
# This variant loads a TLS filler library before custom-labels to exhaust
# the static TLS space and force custom-labels to use DTV.
simple-writer-exhaust-static-tls: $(BUILD_DIR)/process_context-glibc.o
	gcc $(COMMON_CFLAGS) $(COMMON_TLS_FLAGS) \
		-o $(BUILD_DIR)/$@ $(EXHAUST_TLS_SRC) $(BUILD_DIR)/process_context-glibc.o \
		-ldl -lpthread

clean:
	rm -rf $(BUILD_DIR)
