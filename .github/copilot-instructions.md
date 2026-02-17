# Sankshepa Copilot Instructions

You are an expert Rust developer assisting with **Sankshepa**, a high-performance Syslog collector and generator implementing the **LogShrink** methodology with AP-distributed clustering.

## Architecture Guidelines
- **Workspace Structure**: Sankshepa is a Rust workspace with 5 core crates:
    - `crates/protocol`: High-performance `nom` parsers for RFC 3164, 5424, and 6587.
    - `crates/storage`: LogShrink engine (template discovery), columnar storage, and Zstd compression.
    - `crates/ingestion`: Async listeners (TCP, UDP, stubbed BEEP).
    - `crates/cluster`: High Availability (AP) sync using Gossip, Vector Clocks, Merkle Trees, and CRDTs.
    - `crates/ui`: Axum web server providing a real-time log dashboard via SSE.
- **Data Flow**: `Ingestion` -> `Protocol (Parser)` -> `Storage (LogChunk batching)` -> `Cluster Sync` -> `StorageEngine (Zstd Columnar)`.

## Logic Patterns
- **LogShrink Engine**: Found in [crates/storage/src/logshrink.rs](crates/storage/src/logshrink.rs). Group logs by token count, apply similarity threshold (0.5), and extract variables `<*>`.
- **String Interning**: Metadata (hostnames, apps) are interned in a `string_pool` to save space.
- **Async & Concurrency**: 
    - Use `tokio` for I/O and tasks.
    - Prefer `tokio::sync::mpsc` for message passing and `broadcast` for UI/Cluster notifications.
- **Parsing**: Use `nom`. The `UnifiedParser` in [crates/protocol/src/lib.rs](crates/protocol/src/lib.rs) should be the entry point for raw strings.

## Coding Standards
- **Error Handling**: Use `anyhow` for application level; `nom::IResult` for parsing. Avoid `unwrap()` in production code.
- **Logging**: Use `tracing` crate (`info!`, `warn!`, `debug!`, `error!`).
- **Lints**: CI enforces `cargo clippy -- -D warnings`. Avoid collapsible `if` blocks and redundant pattern matching.
- **Type Safety**: Use descriptive type aliases for complex types, especially in clustering and parsing.

## Developer Workflow
- **Build**: `cargo build --release`
- **Test**: `cargo test` for unit tests; [tests/integration_test.rs](tests/integration_test.rs) for E2E.
- **Serve**: `target/release/sankshepa serve --output logs.lshrink --ui-addr 127.0.0.1:8080`
- **Cluster**: Use `--node-id`, `--cluster-addr`, and `--peers` for HA testing.

## Documentation
- Refer to [README.md](README.md) for usage examples.
- Refer to [docs/storage.md](docs/storage.md) for deep-dives into the LogShrink format.
