#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "customlabels_v2.h"
#include "process_context.h"

static volatile sig_atomic_t running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    int ret = 0;

    // Step 1: Publish process-context with key table
    void *process_ctx_mapping = publish_process_context();

    if (!process_ctx_mapping) {
        fprintf(stderr, "WARNING: Failed to publish process-context (reader may not work)\n");
    }

    // Step 2: Initialize the v2 context system
    custom_labels_v2_setup(MAX_RECORD_SIZE);

    printf("Initialized custom_labels_v2 with max_record_size=%d\n", MAX_RECORD_SIZE);

    // Step 3: Allocate a new record
    custom_labels_v2_tl_record_t *record = custom_labels_v2_record_new();
    if (!record) {
        fprintf(stderr, "ERROR: Failed to allocate record\n");
        return 1;
    }

    // Step 4: Set trace context
    custom_labels_v2_record_set_trace(record, TRACE_ID, SPAN_ID, ROOT_SPAN_ID);

    // Step 5: Add attributes
    const char *method = "GET";
    const char *route = "/api/test";
    const char *user = "simple-writer";

    if (custom_labels_v2_record_set_attr(record, METHOD_IDX, method, strlen(method)) != 0) {
        fprintf(stderr, "ERROR: Failed to set method attribute\n");
        ret = 1;
        goto cleanup;
    }

    if (custom_labels_v2_record_set_attr(record, ROUTE_IDX, route, strlen(route)) != 0) {
        fprintf(stderr, "ERROR: Failed to set route attribute\n");
        ret = 1;
        goto cleanup;
    }

    if (custom_labels_v2_record_set_attr(record, USER_IDX, user, strlen(user)) != 0) {
        fprintf(stderr, "ERROR: Failed to set user attribute\n");
        ret = 1;
        goto cleanup;
    }

    // Step 6: Mark record as valid and attach to current thread
    record->valid = 1;
    custom_labels_v2_set_current_record(record);

    printf("Attached context to thread. TLS address: %p\n",
           custom_labels_v2_get_tls_address());
    printf("Simple writer running. Press Ctrl+C to exit.\n");
    fflush(stdout);

    // Step 7: Install signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    // Step 8: Wait for signal
    while (running) {
        pause();
    }

    printf("\nShutting down...\n");

    // Step 9: Cleanup - detach record
    custom_labels_v2_set_current_record(NULL);

cleanup:
    custom_labels_v2_record_free(record);
    printf("Exited cleanly\n");
    return ret;
}
