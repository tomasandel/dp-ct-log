FROM rust:1.82-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y cmake pkg-config libssl-dev python3

# Clone CompactLog
RUN git clone --depth 1 https://github.com/Barre/compact_log.git /build
WORKDIR /build

# Apply skip_inclusion patch
COPY patch_skip_inclusion.py .
RUN python3 patch_skip_inclusion.py

# Build release binary
RUN cargo build --release

# --- Runtime ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/compactlog /usr/local/bin/compactlog

# Storage directory (must exist before startup — CompactLog issue #26)
RUN mkdir -p /data/storage

WORKDIR /app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
