#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

if [ ! -d ~/tmp ] ; then
  mkdir ~/tmp
fi

# Start async-web in the background with custom labels enabled
echo "Starting async-web server..."
cd "$SCRIPT_DIR/async-web"
cargo run --target-dir ~/tmp/async-web -- --writer=custom &
ASYNC_WEB_PID=$!

echo "async-web started with PID: $ASYNC_WEB_PID"

# Give async-web a moment to fully start up
echo "Waiting for async-web to initialize..."
sleep 3

# Start context-reader to monitor async-web
echo "Starting context-reader to monitor PID $ASYNC_WEB_PID..."
cd "$SCRIPT_DIR/context-reader"

# Run context-reader in the foreground
# This will keep the script running and show output
exec cargo run --target-dir ~/tmp/context-reader -- "$ASYNC_WEB_PID" --interval 1000
