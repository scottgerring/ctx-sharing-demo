# Wrap up async-web and context-reader in a dockerfile, so that we can
# easily test our context reading out if we are on some non-linux system.
FROM rustlang/rust:nightly-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy all necessary workspace directories
# TODO - next time I need to iterate on this we should make these copies
# a bit less cache-busting.
COPY async-web ./async-web
COPY context-reader ./context-reader
COPY dd-trace-rs ./dd-trace-rs
COPY opentelemetry-rust ./opentelemetry-rust
COPY custom-labels ./custom-labels

# Build async-web 
WORKDIR /build/async-web
RUN cargo build --release

# Build context-reader
WORKDIR /build/context-reader
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy our binaries over
COPY --from=builder /build/async-web/target/release/async-web /usr/local/bin/async-web
COPY --from=builder /build/context-reader/target/release/context-reader /usr/local/bin/context-reader

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose the port that async-web uses, in case we care about
# hitting it from outside (we probably don't).
EXPOSE 3000

ENTRYPOINT ["/entrypoint.sh"]
