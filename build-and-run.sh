#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="context-sharing-demo"
CONTAINER_NAME="context-sharing-demo-container"

echo "=== Building context-sharing-demo Docker image ==="
echo "This will build both async-web and context-reader in a Linux container"
echo ""

cd "$SCRIPT_DIR"

# Build the Docker image
docker build -t "$IMAGE_NAME" .

echo ""
echo "=== Build complete! ==="
echo ""
echo "=== Starting container ==="
echo ""

# Stop and remove existing container if it exists
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# Run the container
# -it: interactive with TTY
# --rm: automatically remove when stopped (optional, commented out to allow inspection)
# --name: give it a name for easy reference
# -p: expose port 3000 if you want to access the web server from host
docker run -it \
    --name "$CONTAINER_NAME" \
    -p 3000:3000 \
    "$IMAGE_NAME"

echo ""
echo "=== Container stopped ==="
