#!/bin/bash
set -e

# Default values
CLIB="glibc"
LABELS="dynamic"
VALIDATE_MODE=""
USE_EBPF=""

# Parse arguments
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
            if [[ "$LABELS" != "static" && "$LABELS" != "dynamic" && "$LABELS" != "dlopen" ]]; then
                echo "ERROR: --labels must be 'static', 'dynamic', or 'dlopen'"
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
            echo "Usage: $0 [--clib musl|glibc] [--labels static|dynamic|dlopen] [--validate] [--validate-all] [--ebpf]"
            echo ""
            echo "Options:"
            echo "  --clib        C library to use: musl or glibc (default: glibc)"
            echo "  --labels      Labels linking: static, dynamic, or dlopen (default: dynamic)"
            echo "  --validate    Run in validation mode (exit after first successful read)"
            echo "  --validate-all  Run all variant combinations in validation mode"
            echo "  --ebpf        Use eBPF mode instead of ptrace"
            exit 1
            ;;
    esac
done

# Function to run a single variant
run_variant() {
    local labels=$1
    local clib=$2
    local validate=$3
    local use_ebpf=$4

    # Check for invalid combinations
    if [[ "$labels" == "dynamic" && "$clib" == "musl" ]]; then
        echo "ERROR: dynamic + musl is not supported (musl builds are static, cannot link .so)"
        return 1
    fi

    # Set binary name
    if [[ "$labels" == "dlopen" ]]; then
        binary="simple-writer-dlopen-glibc"
    else
        binary="simple-writer-${labels}-${clib}"
    fi

    echo "========================================"
    echo "Testing: $binary"
    echo "Configuration: custom-labels=${labels}, libc=${clib}"
    echo "========================================"

    # Set logging levels - reduce noise
    export RUST_LOG="warn"

    # Step 1: Build custom-labels library
    echo "Building custom-labels library..."
    cd custom-labels

    if [[ "$labels" == "static" ]]; then
        make libcustomlabels.a >/dev/null 2>&1
    else
        make libcustomlabels.so >/dev/null 2>&1
    fi

    cd ..

    # Step 2: Build simple-writer
    echo "Building simple-writer variant..."
    cd simple-writer
    make "$binary" >/dev/null 2>&1
    cd ..

    # Step 3: Verify binary exists
    binary_path="simple-writer/build/$binary"
    if [[ ! -f "$binary_path" ]]; then
        echo "ERROR: Binary not found at $binary_path"
        return 1
    fi

    # Step 4: Build context-reader (always rebuild to pick up changes)
    if [[ "$use_ebpf" == "yes" ]]; then
        echo "Building context-reader with eBPF support..."
        cd context-reader
        cargo xtask build >/dev/null 2>&1
        cd ..
    else
        echo "Building context-reader..."
        cd context-reader
        cargo build >/dev/null 2>&1
        cd ..
    fi

    # Step 5: Start simple-writer
    echo "Starting simple-writer..."
    "$binary_path" &
    writer_pid=$!

    # Give simple-writer a moment to initialize
    sleep 2

    # Check if process is still running
    if ! kill -0 "$writer_pid" 2>/dev/null; then
        echo "ERROR: simple-writer exited prematurely"
        return 1
    fi

    # Step 6: Run context-reader
    local result=0
    local mode_flag=""
    if [[ "$use_ebpf" == "yes" ]]; then
        mode_flag="--mode ebpf"
    fi

    if [[ "$validate" == "yes" ]]; then
        echo "Running context-reader in validate mode${use_ebpf:+ (eBPF)}..."
	cd context-reader
        if sudo env RUST_LOG=info target/debug/context-reader "$writer_pid" --interval 500 --validate-only --timeout 15 $mode_flag; then
            echo "PASS: $binary"
            result=0
        else
            echo "FAIL: $binary"
            result=1
        fi
	cd ..
    else
        echo "Starting context-reader to monitor PID $writer_pid${use_ebpf:+ (eBPF)}..."
        sudo env RUST_LOG=debug ./context-reader/target/debug/context-reader "$writer_pid" --interval 1000 $mode_flag
        result=$?
    fi

    # Cleanup
    kill "$writer_pid" 2>/dev/null || true
    wait "$writer_pid" 2>/dev/null || true

    echo ""
    return $result
}

# Validate-all mode: test all combinations
if [[ "$VALIDATE_MODE" == "all" ]]; then
    echo "Running validation for all simple-writer variants..."
    echo ""

    # Clean build directories to ensure fresh builds for each variant
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
    for labels in static dynamic dlopen; do
        for clib in glibc musl; do
            # Skip invalid combinations
            if [[ "$labels" == "dynamic" && "$clib" == "musl" ]]; then
                continue
            fi

            # Clean and rebuild for this combination
            cd custom-labels && make clean >/dev/null 2>&1 && cd ..

            if run_variant "$labels" "$clib" "yes" "$USE_EBPF"; then
                passed=$((passed + 1))
                if [[ "$labels" == "dlopen" ]]; then
                    results="${results}PASS: simple-writer-dlopen-glibc\n"
                else
                    results="${results}PASS: simple-writer-${labels}-${clib}\n"
                fi
            else
                failed=$((failed + 1))
                if [[ "$labels" == "dlopen" ]]; then
                    results="${results}FAIL: simple-writer-dlopen-glibc\n"
                else
                    results="${results}FAIL: simple-writer-${labels}-${clib}\n"
                fi
            fi
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

# Single variant mode
if [[ "$VALIDATE_MODE" == "single" ]]; then
    run_variant "$LABELS" "$CLIB" "yes" "$USE_EBPF"
    exit $?
fi

# Normal interactive mode
# Check for invalid combinations
if [[ "$LABELS" == "dynamic" && "$CLIB" == "musl" ]]; then
    echo "ERROR: dynamic + musl is not supported (musl builds are static, cannot link .so)"
    exit 1
fi

# Set binary name
if [[ "$LABELS" == "dlopen" ]]; then
    BINARY="simple-writer-dlopen-glibc"
else
    BINARY="simple-writer-${LABELS}-${CLIB}"
fi

echo "Building and running: $BINARY"
echo "Configuration: custom-labels=${LABELS}, libc=${CLIB}"
echo ""

# Set logging levels - reduce noise
export RUST_LOG="warn"

# Step 1: Build custom-labels library
echo "Step 1: Building custom-labels library..."
cd custom-labels

if [[ "$LABELS" == "static" ]]; then
    echo "  Building static library (libcustomlabels.a)..."
    make libcustomlabels.a
else
    # Both dynamic and dlopen variants need the shared library
    echo "  Building shared library (libcustomlabels.so)..."
    make libcustomlabels.so
fi

cd ..
echo ""

# Step 2: Build simple-writer
echo "Step 2: Building simple-writer variant..."
cd simple-writer
make "$BINARY"
cd ..
echo ""

# Step 3: Verify binary
echo "Step 3: Verifying binary..."
BINARY_PATH="simple-writer/build/$BINARY"

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "ERROR: Binary not found at $BINARY_PATH"
    exit 1
fi

echo "  Binary type:"
file "$BINARY_PATH" | sed 's/^/    /'

echo "  Dynamic dependencies:"
if ldd "$BINARY_PATH" 2>/dev/null; then
    ldd "$BINARY_PATH" | sed 's/^/    /'
else
    echo "    (static binary - no dynamic dependencies)"
fi

echo "  Custom labels symbols:"
if nm -D "$BINARY_PATH" 2>/dev/null | grep custom_labels; then
    nm -D "$BINARY_PATH" | grep custom_labels | sed 's/^/    /'
else
    echo "    Checking static symbols..."
    nm "$BINARY_PATH" | grep custom_labels | sed 's/^/    /'
fi
echo ""

# Step 4: Build context-reader
echo "Step 4: Building context-reader${USE_EBPF:+ with eBPF support}..."
cd context-reader
if [[ "$USE_EBPF" == "yes" ]]; then
    cargo xtask build
else
    cargo build
fi
cd ..
echo ""

# Step 5: Start simple-writer
echo "Step 5: Starting simple-writer..."
"$BINARY_PATH" &
WRITER_PID=$!
echo "  simple-writer started with PID: $WRITER_PID"
echo ""

# Give simple-writer a moment to initialize
echo "Waiting for simple-writer to initialize..."
sleep 2
echo ""

# Step 6: Run context-reader
MODE_FLAG=""
if [[ "$USE_EBPF" == "yes" ]]; then
    MODE_FLAG="--mode ebpf"
fi
echo "Step 6: Starting context-reader to monitor PID $WRITER_PID${USE_EBPF:+ (eBPF mode)}..."
cd context-reader
sudo env RUST_LOG=debug target/debug/context-reader "$WRITER_PID" --interval 1000 $MODE_FLAG
cd ..
