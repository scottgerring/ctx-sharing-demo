#!/bin/bash
set -e

# Default values
CLIB="glibc"
LABELS="dynamic"
VALIDATE_MODE=""
USE_EBPF=""

# ============================================================================
# Helper Functions
# ============================================================================

# Get the binary name for a given labels/clib combination
get_binary_name() {
    local labels=$1
    local clib=$2

    if [[ "$labels" == "exhaust-static-tls" ]]; then
        echo "simple-writer-exhaust-static-tls"
    else
        echo "simple-writer-${labels}-${clib}"
    fi
}

# Check if a labels/clib combination is valid
is_valid_combination() {
    local labels=$1
    local clib=$2

    # Only static linking works with musl (context-reader can't resolve TLS for musl dlopen)
    if [[ "$clib" == "musl" && "$labels" != "static" ]]; then
        return 1
    fi
    return 0
}

# Build all components for a given variant
build_variant() {
    local labels=$1
    local clib=$2
    local use_ebpf=$3
    local binary=$(get_binary_name "$labels" "$clib")

    # Build custom-labels library
    cd custom-labels
    if [[ "$labels" == "static" ]]; then
        make libcustomlabels.a >/dev/null 2>&1
    else
        make libcustomlabels.so >/dev/null 2>&1
    fi
    cd ..

    # Build tls-filler library if needed
    if [[ "$labels" == "exhaust-static-tls" ]]; then
        cd tls-filler
        make >/dev/null 2>&1
        cd ..
    fi

    # Build simple-writer
    cd simple-writer
    make "$binary" >/dev/null 2>&1
    cd ..

    # Build context-reader
    cd context-reader
    if [[ "$use_ebpf" == "yes" ]]; then
        cargo xtask build >/dev/null 2>&1
    else
        cargo build >/dev/null 2>&1
    fi
    cd ..
}

# Run the validation test for a variant
run_validation() {
    local labels=$1
    local clib=$2
    local use_ebpf=$3
    local binary=$(get_binary_name "$labels" "$clib")
    local binary_path="simple-writer/build/$binary"
    local mode_flag=""

    if [[ "$use_ebpf" == "yes" ]]; then
        mode_flag="--mode ebpf"
    fi

    # Start simple-writer
    "$binary_path" &
    local writer_pid=$!
    sleep 2

    # Check if process is still running
    if ! kill -0 "$writer_pid" 2>/dev/null; then
        echo "ERROR: simple-writer exited prematurely"
        return 1
    fi

    # Run context-reader in validate mode
    local result=0
    cd context-reader
    if sudo env RUST_LOG=info target/debug/validate "$writer_pid" --interval 500 --timeout 15 $mode_flag; then
        result=0
    else
        result=1
    fi
    cd ..

    # Cleanup
    kill "$writer_pid" 2>/dev/null || true
    wait "$writer_pid" 2>/dev/null || true

    return $result
}

# Run interactive mode (continuous monitoring)
run_interactive() {
    local labels=$1
    local clib=$2
    local use_ebpf=$3
    local binary=$(get_binary_name "$labels" "$clib")
    local binary_path="simple-writer/build/$binary"
    local mode_flag=""

    if [[ "$use_ebpf" == "yes" ]]; then
        mode_flag="--mode ebpf"
    fi

    # Start simple-writer
    echo "Starting simple-writer..."
    "$binary_path" &
    local writer_pid=$!
    echo "  simple-writer started with PID: $writer_pid"
    echo ""

    echo "Waiting for simple-writer to initialize..."
    sleep 2
    echo ""

    # Run context-reader
    echo "Starting context-reader to monitor PID $writer_pid${use_ebpf:+ (eBPF mode)}..."
    cd context-reader
    sudo env RUST_LOG=debug target/debug/tail "$writer_pid" --interval 1000 $mode_flag
    cd ..
}

# ============================================================================
# Argument Parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --clib)
            CLIB="$2"
            if [[ "$CLIB" != "musl" && "$CLIB" != "glibc" ]]; then
                echo "ERROR: --clib must be 'musl' or 'glibc'"
                exit 1
            fi
            shift 2
            ;;
        --labels)
            LABELS="$2"
            if [[ "$LABELS" != "static" && "$LABELS" != "dynamic" && "$LABELS" != "dlopen" && "$LABELS" != "exhaust-static-tls" ]]; then
                echo "ERROR: --labels must be 'static', 'dynamic', 'dlopen', or 'exhaust-static-tls'"
                exit 1
            fi
            shift 2
            ;;
        --validate)
            VALIDATE_MODE="single"
            shift
            ;;
        --validate-all)
            VALIDATE_MODE="all"
            shift
            ;;
        --ebpf)
            USE_EBPF="yes"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--clib musl|glibc] [--labels static|dynamic|dlopen|exhaust-static-tls] [--validate] [--validate-all] [--ebpf]"
            echo ""
            echo "Options:"
            echo "  --clib        C library to use: musl or glibc (default: glibc)"
            echo "  --labels      Labels linking: static, dynamic, dlopen, or exhaust-static-tls (default: dynamic)"
            echo "                exhaust-static-tls: dlopen a filler library first to force DTV usage"
            echo "  --validate    Run in validation mode (exit after first successful read)"
            echo "  --validate-all  Run all variant combinations in validation mode"
            echo "  --ebpf        Use eBPF mode instead of ptrace"
            exit 1
            ;;
    esac
done

# ============================================================================
# Main Execution
# ============================================================================

export RUST_LOG="warn"

# Validate-all mode: test all combinations
if [[ "$VALIDATE_MODE" == "all" ]]; then
    echo "Running validation for all simple-writer variants..."
    echo ""

    # Clean build directories
    echo "Cleaning build directories..."
    rm -rf simple-writer/build
    mkdir -p simple-writer/build
    cd custom-labels && make clean >/dev/null 2>&1 && cd ..
    echo ""

    # Build context-reader once upfront
    echo "Building context-reader${USE_EBPF:+ with eBPF support}..."
    cd context-reader
    if [[ "$USE_EBPF" == "yes" ]]; then
        cargo xtask build 2>&1 | grep -E "Compiling|Finished|error" || true
    else
        cargo build 2>&1 | grep -E "Compiling|Finished|error" || true
    fi
    cd ..
    echo ""

    # Track results
    passed=0
    failed=0
    results=""

    # Test all combinations
    for labels in static dynamic dlopen exhaust-static-tls; do
        for clib in glibc musl; do
            # Skip invalid combinations
            if ! is_valid_combination "$labels" "$clib"; then
                continue
            fi

            binary=$(get_binary_name "$labels" "$clib")
            echo "========================================"
            echo "Testing: $binary"
            echo "========================================"

            # Clean and rebuild custom-labels for this combination
            cd custom-labels && make clean >/dev/null 2>&1 && cd ..

            # Build variant
            echo "Building..."
            build_variant "$labels" "$clib" "$USE_EBPF"

            # Run validation
            echo "Validating${USE_EBPF:+ (eBPF)}..."
            if run_validation "$labels" "$clib" "$USE_EBPF"; then
                echo "PASS: $binary"
                passed=$((passed + 1))
                results="${results}PASS: $binary\n"
            else
                echo "FAIL: $binary"
                failed=$((failed + 1))
                results="${results}FAIL: $binary\n"
            fi
            echo ""
        done
    done

    # Print summary
    echo "========================================"
    echo "VALIDATION SUMMARY"
    echo "========================================"
    echo -e "$results"
    echo "Passed: $passed"
    echo "Failed: $failed"
    echo ""

    if [[ $failed -gt 0 ]]; then
        echo "OVERALL: FAILED"
        exit 1
    else
        echo "OVERALL: PASSED"
        exit 0
    fi
fi

# Single variant mode (validate or interactive)
# Validate combination
if ! is_valid_combination "$LABELS" "$CLIB"; then
    echo "ERROR: $LABELS + $CLIB is not supported"
    exit 1
fi

BINARY=$(get_binary_name "$LABELS" "$CLIB")

echo "Building and running: $BINARY"
echo "Configuration: custom-labels=${LABELS}, libc=${CLIB}"
echo ""

# Build everything
echo "Step 1: Building components..."
build_variant "$LABELS" "$CLIB" "$USE_EBPF"
echo ""

# Verify binary
BINARY_PATH="simple-writer/build/$BINARY"
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "ERROR: Binary not found at $BINARY_PATH"
    exit 1
fi

echo "Step 2: Verifying binary..."
echo "  Binary type:"
file "$BINARY_PATH" | sed 's/^/    /'
echo "  Dynamic dependencies:"
if ldd "$BINARY_PATH" 2>/dev/null; then
    ldd "$BINARY_PATH" | sed 's/^/    /'
else
    echo "    (static binary - no dynamic dependencies)"
fi
echo ""

# Run in validate or interactive mode
if [[ "$VALIDATE_MODE" == "single" ]]; then
    echo "Step 3: Running validation${USE_EBPF:+ (eBPF mode)}..."
    if run_validation "$LABELS" "$CLIB" "$USE_EBPF"; then
        echo "PASS: $BINARY"
        exit 0
    else
        echo "FAIL: $BINARY"
        exit 1
    fi
else
    echo "Step 3: Running interactively${USE_EBPF:+ (eBPF mode)}..."
    run_interactive "$LABELS" "$CLIB" "$USE_EBPF"
fi
