# Sankshepa

![CI Status](https://github.com/sourcepirate/sankshepa/actions/workflows/ci.yml/badge.svg)
![Rust Version](https://img.shields.io/badge/rust-2024-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A high-performance Syslog Collector and Generator with **LogShrink** storage for maximum compression.

## Key Features
- **Multi-Protocol**: Supports RFC 3164 (BSD), RFC 5424 (Structured), and RFC 6587 (TCP Framing).
- **Realtime Dashboard**: Built-in Axum-based web UI with SSE (Server-Sent Events) for live log monitoring.
- **LogShrink Storage**: Deduplicates logs by extracting static templates and dynamic variables into a columnar binary format (`.lshrink`).
- **Modular Architecture**: Organized as a Rust workspace with clean separation between Protocol, Storage, Ingestion, and UI.
- **Efficient Compression**: Uses Delta-encoding for timestamps and Zstd for columnar blocks.

## Project Structure
- `crates/protocol`: High-performance `nom` parsers for syslog.
- `crates/storage`: LogShrink deduplication and columnar storage engine.
- `crates/ingestion`: Async TCP/UDP/BEEP network listeners.
- `crates/ui`: Web server and SSE-based log dashboard.
- `src/`: Main CLI entry point.

## How it Works
1. **Ingestion**: Asynchronous listeners for UDP and TCP (handles Octet Counting and Non-Transparent Framing).
2. **Parsing**: Unified parser identifies RFC version and extracts header fields.
3. **LogShrink Engine**: Batches logs to discover recurring templates using similarity clustering.
4. **Storage**: Stores data in columnar blocks (Timestamps, Hostnames, Template IDs, Variables) with specialized encoding.

## Usage

### Build
```bash
cargo build --release
```

### Start Collector
```bash
# Starts syslog listeners and the Web UI on http://127.0.0.1:8080
./target/release/sankshepa serve --output production.lshrink
```

### High Availability Cluster
Sankshepa supports AP (Available / Partition-tolerant) clustering to synchronize log templates across multiple nodes.

```bash
# Node 1
./target/release/sankshepa serve --node-id node-1 --cluster-addr 127.0.0.1:1701 --output node1.lshrink

# Node 2 (connecting to Node 1)
./target/release/sankshepa serve --node-id node-2 --cluster-addr 127.0.0.1:1702 --peers 127.0.0.1:1701 --output node2.lshrink
```

### Benchmarking Storage Gains
```bash
# Generate 100k logs and measure compression efficiency
./target/release/sankshepa bench --count 100000 --output bench.lshrink
```

### Generate Test Logs
```bash
./target/release/sankshepa generate --count 1000 --protocol tcp
```

### Query & Reconstruct Logs
```bash
./target/release/sankshepa query --input production.lshrink
# Filter by template ID
./target/release/sankshepa query --input production.lshrink --template-id 0
```

## Testing
Comprehensive unit and integration tests are included:
```bash
cargo test
```
The integration tests verify the end-to-end pipeline (generation -> ingestion -> storage -> query).
