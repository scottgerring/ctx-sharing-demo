# Datadog Java Demo Application

A simple Java application that continuously generates traces and spans for demonstration purposes with the Datadog APM tracer.

## Prerequisites

- Java 11 or higher
- Gradle (included via wrapper, no installation needed)
- Datadog Java tracer agent JAR

## Building the Application

```bash
./gradlew build
```

This will create a JAR file at `build/libs/demo-java-1.0-SNAPSHOT.jar`.

## Downloading the Datadog Tracer

Download the latest Datadog Java tracer:

```bash
curl -Lo dd-java-agent.jar https://dtdg.co/latest-java-tracer
```

## Running with Datadog Tracer

### Using the Start Script (Recommended)

The easiest way to run the application is using the provided start script:

```bash
./start.sh [OPTIONS] [agent-jar-path]
```

If no path is provided, the script will automatically download the latest Datadog Java tracer to `./dd-java-agent.jar` (only downloads once).

#### Options

- `--profiling-enabled <true|false>` - Enable/disable profiling (default: false)
- `--trace-enabled <true|false>` - Enable/disable tracing (default: true)
- `-D<property>=<value>` - Pass additional Java system properties
- `--help` - Show help message

#### Examples

```bash
# Automatic download (if not present) and run
./start.sh

# Enable profiling
./start.sh --profiling-enabled true

# Enable only profiling, disable tracing
./start.sh --trace-enabled false --profiling-enabled true

# Use specific agent JAR
./start.sh ./dd-java-agent.jar

# Enable profiling with specific agent JAR
./start.sh --profiling-enabled true ./dd-java-agent.jar

# With custom service name (via environment variable)
DD_SERVICE=my-service ./start.sh --profiling-enabled true

# With additional Java options
./start.sh --profiling-enabled true -Ddd.trace.debug=true

# Complex example
DD_SERVICE=order-service DD_ENV=production ./start.sh --profiling-enabled true --trace-enabled true
```

The start script will:
- Download the latest Datadog agent JAR if not provided and not already present
- Check if the Datadog agent JAR exists (if path specified)
- Build the application if needed (using Gradle)
- Launch the app with proper configuration including:
  - Profiling settings (enabled/disabled)
  - Tracing settings (enabled/disabled)
  - Experimental process context sharing (`dd.profiling.experimental.process_context.enabled=true`)
- Display helpful error messages if something goes wrong

You can still use environment variables for basic configuration:
- `DD_SERVICE` - Service name (default: demo-java)
- `DD_ENV` - Environment (default: development)
- `DD_VERSION` - Application version (default: 1.0.0)

### Manual Execution

Alternatively, run the application manually with the Datadog Java agent attached:

```bash
java -javaagent:dd-java-agent.jar \
  -Ddd.service=demo-java \
  -Ddd.env=development \
  -Ddd.version=1.0.0 \
  -Ddd.profiling.enabled=false \
  -Ddd.profiling.ddprof.enabled=false \
  -Ddd.trace.enabled=true \
  -Ddd.profiling.experimental.process_context.enabled=true \
  -jar build/libs/demo-java-1.0-SNAPSHOT.jar
```

### Configuration Options

You can customize the Datadog agent behavior with these system properties:

- `-Ddd.service=<service-name>` - Service name (default: demo-java)
- `-Ddd.env=<environment>` - Environment (e.g., development, staging, production)
- `-Ddd.version=<version>` - Application version
- `-Ddd.profiling.enabled=<true|false>` - Enable profiling (default: false)
- `-Ddd.profiling.ddprof.enabled=<true|false>` - Enable ddprof profiler (default: false)
- `-Ddd.trace.enabled=<true|false>` - Enable tracing (default: true)
- `-Ddd.profiling.experimental.process_context.enabled=<true|false>` - Enable process context sharing (experimental)
- `-Ddd.trace.debug=true` - Enable debug logging for traces
- `-Ddd.agent.host=<hostname>` - Datadog Agent host (default: localhost)
- `-Ddd.agent.port=<port>` - Datadog Agent port (default: 8126)

### Example with Debug Mode

```bash
java -javaagent:dd-java-agent.jar \
  -Ddd.service=demo-java \
  -Ddd.env=development \
  -Ddd.trace.debug=true \
  -Ddd.profiling.enabled=true \
  -Ddd.profiling.ddprof.enabled=true \
  -Ddd.profiling.experimental.process_context.enabled=true \
  -jar build/libs/demo-java-1.0-SNAPSHOT.jar
```

## What the Application Does

The demo application continuously performs various simulated operations:

1. **Order Processing** - Simulates an e-commerce order flow
   - Order validation
   - Inventory checking with database queries
   - Payment processing with external API calls

2. **User Data Fetching** - Simulates user data retrieval
   - Database queries to fetch user information
   - Cache lookups (Redis) with occasional cache misses

3. **Calculations** - Simulates complex computational operations

Each operation creates traces with multiple spans, including:
- Custom span tags
- Simulated database queries
- External API calls
- Cache operations
- Occasional simulated errors (10% failure rate for payments)

## Stopping the Application

Press `Ctrl+C` to stop the application.

## Viewing Traces

Once the application is running with the Datadog agent:

1. Ensure your Datadog Agent is running and configured
2. Navigate to the Datadog APM interface
3. Look for the service name (default: `demo-java`)
4. View traces, spans, and performance metrics

## Generated Trace Operations

The application generates the following trace operations:

- `process.order` - Main order processing operation
- `validate.order` - Order validation span
- `check.inventory` - Inventory check operation
- `process.payment` - Payment processing operation
- `fetch.user` - User data fetch operation
- `load.preferences` - User preferences loading
- `perform.calculation` - Calculation operation
- `database.query` - Database query spans
- `external.api.call` - External API call spans
- `cache.get` - Cache lookup spans
