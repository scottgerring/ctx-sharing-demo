#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_info() {
    echo -e "${YELLOW}$1${NC}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS] [agent-jar-path]"
    echo ""
    echo "Options:"
    echo "  --profiling-enabled <true|false>   Enable/disable profiling (default: false)"
    echo "  --trace-enabled <true|false>       Enable/disable tracing (default: true)"
    echo "  --help                             Show this help message"
    echo ""
    echo "Arguments:"
    echo "  agent-jar-path                     Path to dd-java-agent.jar (optional, will auto-download if not provided)"
    echo ""
    echo "Examples:"
    echo "  $0                                                    # Auto-download agent and run"
    echo "  $0 --profiling-enabled true                          # Run with profiling enabled"
    echo "  $0 --trace-enabled false --profiling-enabled true    # Only profiling, no tracing"
    echo "  $0 ./dd-java-agent.jar                               # Use specific agent JAR"
    echo "  $0 --profiling-enabled true ./dd-java-agent.jar      # Profiling with specific agent"
    echo ""
    echo "Environment variables (can still be used):"
    echo "  DD_SERVICE        Service name (default: demo-java)"
    echo "  DD_ENV            Environment (default: development)"
    echo "  DD_VERSION        Application version (default: 1.0.0)"
}

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DD_PROFILING_ENABLED="${DD_PROFILING_ENABLED:-false}"
DD_TRACE_ENABLED="${DD_TRACE_ENABLED:-true}"
DD_AGENT_JAR=""
EXTRA_JAVA_OPTS=()

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profiling-enabled)
            DD_PROFILING_ENABLED="$2"
            shift 2
            ;;
        --trace-enabled)
            DD_TRACE_ENABLED="$2"
            shift 2
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        -D*)
            # Collect any -D Java options
            EXTRA_JAVA_OPTS+=("$1")
            shift
            ;;
        *)
            # Assume it's the agent JAR path if it doesn't start with -
            if [[ ! "$1" =~ ^- ]]; then
                DD_AGENT_JAR="$1"
                shift
            else
                print_error "Unknown option: $1"
                echo ""
                print_usage
                exit 1
            fi
            ;;
    esac
done

# Validate boolean values
if [[ "$DD_PROFILING_ENABLED" != "true" && "$DD_PROFILING_ENABLED" != "false" ]]; then
    print_error "Invalid value for --profiling-enabled: $DD_PROFILING_ENABLED (must be 'true' or 'false')"
    exit 1
fi

if [[ "$DD_TRACE_ENABLED" != "true" && "$DD_TRACE_ENABLED" != "false" ]]; then
    print_error "Invalid value for --trace-enabled: $DD_TRACE_ENABLED (must be 'true' or 'false')"
    exit 1
fi

# Handle agent JAR
if [ -z "$DD_AGENT_JAR" ]; then
    # No argument provided, use default location and download if needed
    DD_AGENT_JAR="$SCRIPT_DIR/dd-java-agent.jar"

    if [ ! -f "$DD_AGENT_JAR" ]; then
        print_info "No Datadog agent JAR specified and none found at default location."
        print_info "Downloading latest Datadog Java tracer..."
        echo ""

        if ! curl -Lo "$DD_AGENT_JAR" https://dtdg.co/latest-java-tracer; then
            print_error "Failed to download Datadog agent JAR"
            exit 1
        fi

        print_success "Downloaded Datadog agent to: $DD_AGENT_JAR"
        echo ""
    else
        print_info "Using existing Datadog agent JAR at: $DD_AGENT_JAR"
        echo ""
    fi
else
    # Check if the specified dd-java-agent.jar file exists
    if [ ! -f "$DD_AGENT_JAR" ]; then
        print_error "Datadog agent JAR not found at: $DD_AGENT_JAR"
        echo ""
        echo "Download it with:"
        echo "  curl -Lo dd-java-agent.jar https://dtdg.co/latest-java-tracer"
        exit 1
    fi
fi

JAR_FILE="$SCRIPT_DIR/build/libs/demo-java-1.0-SNAPSHOT.jar"

# Check if the application JAR exists
if [ ! -f "$JAR_FILE" ]; then
    print_error "Application JAR not found at: $JAR_FILE"
    echo ""
    print_info "Building the application..."
    cd "$SCRIPT_DIR"
    ./gradlew build

    if [ $? -ne 0 ]; then
        print_error "Build failed"
        exit 1
    fi
    print_success "Build successful!"
    echo ""
fi

# Default Datadog configuration from environment variables
DD_SERVICE="${DD_SERVICE:-demo-java}"
DD_ENV="${DD_ENV:-development}"
DD_VERSION="${DD_VERSION:-1.0.0}"

print_info "Starting Datadog Java Demo Application..."
echo ""
echo "Configuration:"
echo "  DD Agent JAR:       $DD_AGENT_JAR"
echo "  App JAR:            $JAR_FILE"
echo "  Service:            $DD_SERVICE"
echo "  Environment:        $DD_ENV"
echo "  Version:            $DD_VERSION"
echo "  Profiling Enabled:  $DD_PROFILING_ENABLED"
echo "  Trace Enabled:      $DD_TRACE_ENABLED"
echo ""
print_info "Press Ctrl+C to stop the application"
echo ""
echo "----------------------------------------"
echo ""

# Run the application with Datadog agent
java -javaagent:"$DD_AGENT_JAR" \
  -Ddd.service="$DD_SERVICE" \
  -Ddd.env="$DD_ENV" \
  -Ddd.version="$DD_VERSION" \
  -Ddd.profiling.enabled="$DD_PROFILING_ENABLED" \
  -Ddd.profiling.ddprof.enabled="$DD_PROFILING_ENABLED" \
  -Ddd.trace.enabled="$DD_TRACE_ENABLED" \
  -Ddd.profiling.experimental.process_context.enabled=true \
  "${EXTRA_JAVA_OPTS[@]}" \
  -jar "$JAR_FILE"
