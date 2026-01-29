#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <libgen.h>
#include <limits.h>
#include <dlfcn.h>
#include <pthread.h>
#include "customlabels_v2.h"
#include "process_context.h"

static volatile sig_atomic_t running = 1;

// Function pointers - made global so worker thread can use them
static void (*g_v2_setup)(uint64_t);
static custom_labels_v2_tl_record_t* (*g_v2_record_new)(void);
static void (*g_v2_record_free)(custom_labels_v2_tl_record_t*);
static void (*g_v2_record_set_trace)(custom_labels_v2_tl_record_t*, const uint8_t[16], const uint8_t[8]);
static int (*g_v2_record_set_attr)(custom_labels_v2_tl_record_t*, uint8_t, const void*, uint8_t);
static custom_labels_v2_tl_record_t* (*g_v2_set_current_record)(custom_labels_v2_tl_record_t*);
static void* (*g_v2_get_tls_address)(void);

static void *worker_thread(void *arg) {
    (void)arg;

    printf("[worker] Starting worker thread (tid visible to reader)\n");

    // Allocate a new record for this thread
    custom_labels_v2_tl_record_t *record = g_v2_record_new();
    if (!record) {
        fprintf(stderr, "[worker] ERROR: Failed to allocate record\n");
        return NULL;
    }

    // Set trace context
    g_v2_record_set_trace(record, TRACE_ID, SPAN_ID);

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
 * Get the path to libcustomlabels.so relative to the executable.
 * The binary is at simple-writer/build/<name> and the library is at
 * custom-labels/libcustomlabels.so, so the relative path from the
 * binary's directory is ../../custom-labels/libcustomlabels.so
 */
static char *get_library_path(void) {
    static char lib_path[PATH_MAX];
    char exe_path[PATH_MAX];

    // Read the executable's path from /proc/self/exe
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        perror("readlink /proc/self/exe");
        return NULL;
    }
    exe_path[len] = '\0';

    // Get the directory containing the executable
    char *exe_dir = dirname(exe_path);

    // Construct path: <exe_dir>/../../custom-labels/libcustomlabels.so
    snprintf(lib_path, sizeof(lib_path), "%s/../../custom-labels/libcustomlabels.so", exe_dir);

    return lib_path;
}

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    int ret = 0;

    // Step 0: Load libcustomlabels.so via dlopen
    char *lib_path = get_library_path();
    if (!lib_path) {
        fprintf(stderr, "ERROR: Failed to determine library path\n");
        return 1;
    }
    printf("Loading library: %s\n", lib_path);

    void *lib_handle = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
    if (!lib_handle) {
        fprintf(stderr, "ERROR: dlopen failed: %s\n", dlerror());
        return 1;
    }
    printf("Library loaded successfully\n");

    // Resolve function pointers into globals (so worker thread can use them)
    g_v2_setup = (void (*)(uint64_t))dlsym(lib_handle, "custom_labels_v2_setup");
    g_v2_record_new = (custom_labels_v2_tl_record_t* (*)(void))dlsym(lib_handle, "custom_labels_v2_record_new");
    g_v2_record_free = (void (*)(custom_labels_v2_tl_record_t*))dlsym(lib_handle, "custom_labels_v2_record_free");
    g_v2_record_set_trace = (void (*)(custom_labels_v2_tl_record_t*, const uint8_t[16], const uint8_t[8]))
        dlsym(lib_handle, "custom_labels_v2_record_set_trace");
    g_v2_record_set_attr = (int (*)(custom_labels_v2_tl_record_t*, uint8_t, const void*, uint8_t))
        dlsym(lib_handle, "custom_labels_v2_record_set_attr");
    g_v2_set_current_record = (custom_labels_v2_tl_record_t* (*)(custom_labels_v2_tl_record_t*))
        dlsym(lib_handle, "custom_labels_v2_set_current_record");
    g_v2_get_tls_address = (void* (*)(void))dlsym(lib_handle, "custom_labels_v2_get_tls_address");

    if (!g_v2_setup || !g_v2_record_new || !g_v2_record_free || !g_v2_record_set_trace ||
        !g_v2_record_set_attr || !g_v2_set_current_record || !g_v2_get_tls_address) {
        fprintf(stderr, "ERROR: Failed to resolve symbols: %s\n", dlerror());
        dlclose(lib_handle);
        return 1;
    }
    printf("All symbols resolved\n");

    // Step 1: Publish process-context with key table
    void *process_ctx_mapping = publish_process_context();

    if (!process_ctx_mapping) {
        fprintf(stderr, "WARNING: Failed to publish process-context (reader may not work)\n");
    }

    // Step 2: Initialize the v2 context system
    g_v2_setup(MAX_RECORD_SIZE);

    printf("Initialized custom_labels_v2 with max_record_size=%d\n", MAX_RECORD_SIZE);

    // Step 3: Allocate a new record for main thread
    custom_labels_v2_tl_record_t *record = g_v2_record_new();
    if (!record) {
        fprintf(stderr, "ERROR: Failed to allocate record\n");
        dlclose(lib_handle);
        return 1;
    }

    // Step 4: Set trace context
    g_v2_record_set_trace(record, TRACE_ID, SPAN_ID);

    // Step 5: Add attributes
    const char *method = "GET";
    const char *route = "/api/dlopen-test";
    const char *user = "dlopen-main";

    if (g_v2_record_set_attr(record, METHOD_IDX, method, strlen(method)) != 0) {
        fprintf(stderr, "ERROR: Failed to set method attribute\n");
        ret = 1;
        goto cleanup;
    }

    if (g_v2_record_set_attr(record, ROUTE_IDX, route, strlen(route)) != 0) {
        fprintf(stderr, "ERROR: Failed to set route attribute\n");
        ret = 1;
        goto cleanup;
    }

    if (g_v2_record_set_attr(record, USER_IDX, user, strlen(user)) != 0) {
        fprintf(stderr, "ERROR: Failed to set user attribute\n");
        ret = 1;
        goto cleanup;
    }

    // Step 6: Mark record as valid and attach to current thread
    record->valid = 1;
    g_v2_set_current_record(record);

    printf("[main] Attached context to thread. TLS address: %p\n", g_v2_get_tls_address());
    fflush(stdout);

    // Step 7: Spawn a worker thread that also uses TLS
    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_thread, NULL) != 0) {
        perror("pthread_create");
        ret = 1;
        goto cleanup;
    }

    printf("Simple writer (dlopen variant) running. Press Ctrl+C to exit.\n");
    fflush(stdout);

    // Step 8: Install signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    // Step 9: Spin to generate CPU samples for eBPF profiler
    volatile uint64_t counter = 0;
    while (running) {
        counter++;
        if ((counter & 0xFFFFFF) == 0) {
            usleep(1);
        }
    }

    printf("\nShutting down...\n");

    // Step 10: Cleanup - wait for worker, detach record
    pthread_join(worker, NULL);
    g_v2_set_current_record(NULL);

cleanup:
    g_v2_record_free(record);
    dlclose(lib_handle);
    printf("Exited cleanly\n");
    return ret;
}
