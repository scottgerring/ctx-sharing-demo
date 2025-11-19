#!/bin/bash
set -e

# Start async-web in the background with custom labels enabled
echo "Starting async-web server..."
/usr/local/bin/async-web --writer=custom &
ASYNC_WEB_PID=$!

echo "async-web started with PID: $ASYNC_WEB_PID"

# Give async-web a moment to fully start up
sleep 3

# Start context-reader to monitor async-web
echo "Starting context-reader to monitor PID $ASYNC_WEB_PID..."

# Run context-reader in the foreground
# This will keep the container running and show output
exec /usr/local/bin/context-reader "$ASYNC_WEB_PID" --interval 1000
