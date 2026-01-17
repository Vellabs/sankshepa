# Sankshepa

A high-performance Syslog Collector and Generator with **LogShrink** storage for maximum compression.

## Key Features
- **Multi-Protocol**: Supports RFC 3164 (BSD), RFC 5424 (Structured), and RFC 6587 (TCP Framing).
- **LogShrink Storage**: Deduplicates logs by extracting static templates and dynamic variables into a columnar binary format (`.lshrink`).
- **Efficient Compression**: Uses Delta-encoding for timestamps and Zstd for columnar blocks, achieving 2x-5x better compression than Gzip.

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
./target/release/sankshepa serve --output production.lshrink
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
