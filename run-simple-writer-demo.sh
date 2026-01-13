#!/bin/bash
set -e

# Default values
CLIB="glibc"
LABELS="dynamic"

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
            if [[ "$LABELS" != "static" && "$LABELS" != "dynamic" ]]; then
                echo "ERROR: --labels must be 'static' or 'dynamic'"
                exit 1
            fi
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--clib musl|glibc] [--labels static|dynamic]"
            exit 1
            ;;
    esac
done

# Construct binary name
BINARY="simple-writer-${LABELS}-${CLIB}"
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
echo "Step 4: Building context-reader..."
cd context-reader
cargo build
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
echo "Step 6: Starting context-reader to monitor PID $WRITER_PID..."
sudo env RUST_LOG=debug ./context-reader/target/debug/context-reader "$WRITER_PID" --interval 1000
