/**
 * simple-writer-exhaust-static-tls.c
 *
 * This variant first dlopen's a "filler" library that consumes all available
 * static TLS space, then dlopen's custom-labels. This forces custom-labels
 * to use the DTV (Dynamic Thread Vector) for TLS allocation instead of
 * static TLS.
 *
 * This tests the context-reader's DTV lookup path.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <libgen.h>
#include <linux/limits.h>
#include <dlfcn.h>
#include <pthread.h>
#include "customlabels_v2.h"
#include "process_context.h"

static volatile sig_atomic_t running = 1;

// Function pointers for custom-labels
static void (*g_v2_setup)(uint64_t);
static custom_labels_v2_tl_record_t* (*g_v2_record_new)(void);
static void (*g_v2_record_free)(custom_labels_v2_tl_record_t*);
static void (*g_v2_record_set_trace)(custom_labels_v2_tl_record_t*, const uint8_t[16], const uint8_t[8], const uint8_t[8]);
static int (*g_v2_record_set_attr)(custom_labels_v2_tl_record_t*, uint8_t, const void*, uint8_t);
static custom_labels_v2_tl_record_t* (*g_v2_set_current_record)(custom_labels_v2_tl_record_t*);
static void* (*g_v2_get_tls_address)(void);

// Function pointers for tls-filler
static void (*g_filler_init)(void);
static void* (*g_filler_get_address)(void);

static void *worker_thread(void *arg) {
    (void)arg;

    printf("[worker] Starting worker thread (tid visible to reader)\n");

    // Touch filler TLS in this thread too
    if (g_filler_init) {
        g_filler_init();
        printf("[worker] Filler TLS address: %p\n", g_filler_get_address());
    }

    // Allocate a new record for this thread
    custom_labels_v2_tl_record_t *record = g_v2_record_new();
    if (!record) {
        fprintf(stderr, "[worker] ERROR: Failed to allocate record\n");
        return NULL;
    }

    // Set trace context
    g_v2_record_set_trace(record, TRACE_ID, SPAN_ID, ROOT_SPAN_ID);

    // Add attributes
    const char *method = "POST";
    const char *route = "/api/worker";
    const char *user = "worker-thread";

    g_v2_record_set_attr(record, METHOD_IDX, method, strlen(method));
    g_v2_record_set_attr(record, ROUTE_IDX, route, strlen(route));
    g_v2_record_set_attr(record, USER_IDX, user, strlen(user));

    // Mark valid and attach
    record->valid = 1;
    g_v2_set_current_record(record);

    printf("[worker] Attached context. TLS address: %p\n", g_v2_get_tls_address());
    fflush(stdout);

    // Spin to generate CPU samples for eBPF profiler
    volatile uint64_t counter = 0;
    while (running) {
        counter++;
        if ((counter & 0xFFFFFF) == 0) {
            usleep(1);
        }
    }

    // Cleanup
    g_v2_set_current_record(NULL);
    g_v2_record_free(record);
    printf("[worker] Worker thread exiting\n");
    return NULL;
}

/**
 * Get the directory containing the executable.
 */
static char *get_exe_dir(void) {
    static char exe_dir[PATH_MAX];
    char exe_path[PATH_MAX];

    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        perror("readlink /proc/self/exe");
        return NULL;
    }
    exe_path[len] = '\0';

    char *dir = dirname(exe_path);
    strncpy(exe_dir, dir, sizeof(exe_dir) - 1);
    exe_dir[sizeof(exe_dir) - 1] = '\0';

    return exe_dir;
}

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    int ret = 0;
    void *filler_handle = NULL;
    void *filler2_handle = NULL;
    void *filler3_handle = NULL;
    void *labels_handle = NULL;

    char *exe_dir = get_exe_dir();
    if (!exe_dir) {
        fprintf(stderr, "ERROR: Failed to determine executable directory\n");
        return 1;
    }

    // =====================================================================
    // Step 1: dlopen multiple TLS filler libraries FIRST
    // Each 2KB allocation consumes part of glibc's static TLS surplus.
    // Loading multiple libraries ensures we exhaust the surplus completely.
    // =====================================================================
    char filler_path[PATH_MAX];

    // Load filler 1
    snprintf(filler_path, sizeof(filler_path), "%s/../../tls-filler/libtlsfiller.so", exe_dir);
    printf("Loading TLS filler library 1: %s\n", filler_path);
    filler_handle = dlopen(filler_path, RTLD_NOW | RTLD_GLOBAL);
    if (!filler_handle) {
        fprintf(stderr, "ERROR: dlopen filler 1 failed: %s\n", dlerror());
        return 1;
    }
    g_filler_init = (void (*)(void))dlsym(filler_handle, "tls_filler_init");
    g_filler_get_address = (void* (*)(void))dlsym(filler_handle, "tls_filler_get_address");
    if (g_filler_init && g_filler_get_address) {
        g_filler_init();
        printf("TLS filler 1 initialized. TLS address: %p\n", g_filler_get_address());
    }

    // Load filler 2
    snprintf(filler_path, sizeof(filler_path), "%s/../../tls-filler/libtlsfiller2.so", exe_dir);
    printf("Loading TLS filler library 2: %s\n", filler_path);
    filler2_handle = dlopen(filler_path, RTLD_NOW | RTLD_GLOBAL);
    if (!filler2_handle) {
        fprintf(stderr, "ERROR: dlopen filler 2 failed: %s\n", dlerror());
        ret = 1;
        goto cleanup;
    }
    void (*filler2_init)(void) = (void (*)(void))dlsym(filler2_handle, "tls_filler2_init");
    void* (*filler2_get_addr)(void) = (void* (*)(void))dlsym(filler2_handle, "tls_filler2_get_address");
    if (filler2_init && filler2_get_addr) {
        filler2_init();
        printf("TLS filler 2 initialized. TLS address: %p\n", filler2_get_addr());
    }

    // Load filler 3
    snprintf(filler_path, sizeof(filler_path), "%s/../../tls-filler/libtlsfiller3.so", exe_dir);
    printf("Loading TLS filler library 3: %s\n", filler_path);
    filler3_handle = dlopen(filler_path, RTLD_NOW | RTLD_GLOBAL);
    if (!filler3_handle) {
        fprintf(stderr, "ERROR: dlopen filler 3 failed: %s\n", dlerror());
        ret = 1;
        goto cleanup;
    }
    void (*filler3_init)(void) = (void (*)(void))dlsym(filler3_handle, "tls_filler3_init");
    void* (*filler3_get_addr)(void) = (void* (*)(void))dlsym(filler3_handle, "tls_filler3_get_address");
    if (filler3_init && filler3_get_addr) {
        filler3_init();
        printf("TLS filler 3 initialized. TLS address: %p\n", filler3_get_addr());
    }

    printf("All TLS filler libraries loaded (3x 256 bytes = 768 bytes total)\n");

    // =====================================================================
    // Step 2: dlopen custom-labels AFTER all fillers
    // With surplus exhausted, this should force custom-labels to use DTV
    // =====================================================================
    char labels_path[PATH_MAX];
    snprintf(labels_path, sizeof(labels_path), "%s/../../custom-labels/libcustomlabels.so", exe_dir);

    printf("Loading custom-labels library: %s\n", labels_path);
    labels_handle = dlopen(labels_path, RTLD_NOW | RTLD_GLOBAL);
    if (!labels_handle) {
        fprintf(stderr, "ERROR: dlopen custom-labels failed: %s\n", dlerror());
        ret = 1;
        goto cleanup;
    }
    printf("Custom-labels loaded successfully\n");

    // Resolve custom-labels function pointers
    g_v2_setup = (void (*)(uint64_t))dlsym(labels_handle, "custom_labels_v2_setup");
    g_v2_record_new = (custom_labels_v2_tl_record_t* (*)(void))dlsym(labels_handle, "custom_labels_v2_record_new");
    g_v2_record_free = (void (*)(custom_labels_v2_tl_record_t*))dlsym(labels_handle, "custom_labels_v2_record_free");
    g_v2_record_set_trace = (void (*)(custom_labels_v2_tl_record_t*, const uint8_t[16], const uint8_t[8], const uint8_t[8]))
        dlsym(labels_handle, "custom_labels_v2_record_set_trace");
    g_v2_record_set_attr = (int (*)(custom_labels_v2_tl_record_t*, uint8_t, const void*, uint8_t))
        dlsym(labels_handle, "custom_labels_v2_record_set_attr");
    g_v2_set_current_record = (custom_labels_v2_tl_record_t* (*)(custom_labels_v2_tl_record_t*))
        dlsym(labels_handle, "custom_labels_v2_set_current_record");
    g_v2_get_tls_address = (void* (*)(void))dlsym(labels_handle, "custom_labels_v2_get_tls_address");

    if (!g_v2_setup || !g_v2_record_new || !g_v2_record_free || !g_v2_record_set_trace ||
        !g_v2_record_set_attr || !g_v2_set_current_record || !g_v2_get_tls_address) {
        fprintf(stderr, "ERROR: Failed to resolve custom-labels symbols: %s\n", dlerror());
        ret = 1;
        goto cleanup;
    }
    printf("All custom-labels symbols resolved\n");

    // =====================================================================
    // Step 3: Publish process-context with key table
    // =====================================================================
    void *process_ctx_mapping = publish_process_context();
    if (!process_ctx_mapping) {
        fprintf(stderr, "WARNING: Failed to publish process-context (reader may not work)\n");
    }

    // =====================================================================
    // Step 4: Initialize and use custom-labels
    // =====================================================================
    g_v2_setup(MAX_RECORD_SIZE);
    printf("Initialized custom_labels_v2 with max_record_size=%d\n", MAX_RECORD_SIZE);

    custom_labels_v2_tl_record_t *record = g_v2_record_new();
    if (!record) {
        fprintf(stderr, "ERROR: Failed to allocate record\n");
        ret = 1;
        goto cleanup;
    }

    g_v2_record_set_trace(record, TRACE_ID, SPAN_ID, ROOT_SPAN_ID);

    const char *method = "GET";
    const char *route = "/api/exhaust-static-tls";
    const char *user = "dtv-test";

    if (g_v2_record_set_attr(record, METHOD_IDX, method, strlen(method)) != 0 ||
        g_v2_record_set_attr(record, ROUTE_IDX, route, strlen(route)) != 0 ||
        g_v2_record_set_attr(record, USER_IDX, user, strlen(user)) != 0) {
        fprintf(stderr, "ERROR: Failed to set attributes\n");
        ret = 1;
        goto cleanup_record;
    }

    record->valid = 1;
    g_v2_set_current_record(record);

    printf("[main] Attached context. TLS address: %p\n", g_v2_get_tls_address());
    fflush(stdout);

    // Spawn worker thread
    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_thread, NULL) != 0) {
        perror("pthread_create");
        ret = 1;
        goto cleanup_record;
    }

    printf("Simple writer (exhaust-static-tls variant) running. Press Ctrl+C to exit.\n");
    printf("NOTE: custom-labels should be using DTV instead of static TLS!\n");
    fflush(stdout);

    // Install signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    // Spin to generate CPU samples
    volatile uint64_t counter = 0;
    while (running) {
        counter++;
        if ((counter & 0xFFFFFF) == 0) {
            usleep(1);
        }
    }

    printf("\nShutting down...\n");

    pthread_join(worker, NULL);
    g_v2_set_current_record(NULL);

cleanup_record:
    g_v2_record_free(record);

cleanup:
    if (labels_handle) dlclose(labels_handle);
    if (filler3_handle) dlclose(filler3_handle);
    if (filler2_handle) dlclose(filler2_handle);
    if (filler_handle) dlclose(filler_handle);
    printf("Exited cleanly\n");
    return ret;
}
