# Build stage
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/sankshepa

# Copy the entire workspace
COPY . .

# Build the application
RUN cargo build --release

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /usr/src/sankshepa/target/release/sankshepa /usr/local/bin/sankshepa

# Expose ports
# UDP/TCP Syslog
EXPOSE 1514/udp
EXPOSE 1514/tcp
# BEEP
EXPOSE 1601
# UI
EXPOSE 8080
# Cluster
EXPOSE 1701/udp

# Default environment variables
ENV RUST_LOG=info,sankshepa=debug

ENTRYPOINT ["sankshepa"]
CMD ["serve", "--udp-addr", "0.0.0.0:1514", "--tcp-addr", "0.0.0.0:1514", "--beep-addr", "0.0.0.0:1601", "--ui-addr", "0.0.0.0:8080", "--cluster-addr", "0.0.0.0:1701"]
