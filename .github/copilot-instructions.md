# Sankshepa Copilot Instructions

You are an expert Rust developer assisting with **Sankshepa**, a high-performance Syslog collector and generator implementing the **LogShrink** methodology.

## Project Vision
Sankshepa aims to provide a compliant, high-speed syslog infrastructure that minimizes storage footprint by deduplicating logs into static templates and dynamic variables, stored in a compressed columnar format.

## Core Architecture
- **Protocol Layer (`src/protocol/`)**: High-performance `nom` parsers for RFC 3164 and RFC 5424. The `UnifiedParser` uses heuristics to detect the protocol version.
- **Ingestion Layer (`src/ingestion/`)**: Concurrent listeners using `tokio`. TCP ingestion must handle **RFC 6587** (Octet Counting and Non-Transparent Framing).
- **LogShrink Engine (`src/storage/logshrink.rs`)**: 
    - Groups logs by token count.
    - Uses similarity clustering (threshold ≥ 0.5) to deduce templates.
    - Replaces variable parts with `<*>`.
- **Storage Layer (`src/storage/mod.rs`)**: Columnar storage using `postcard` for serialization, delta-encoding for timestamps, and `zstd` for block compression.

## Coding Standards
- **Strict Linting**: The CI enforces `cargo clippy -- -D warnings`. Avoid collapsible `if` blocks, redundant pattern matching, and complex types without aliases.
- **Formatting**: Always run `cargo fmt` before committing.
- **Async Runtime**: Use `tokio` for all I/O and task orchestration.
- **Error Handling**: Use `anyhow` for application-level errors and `nom::IResult` for parsing.
- **Type Safety**: Prefer explicit type aliases for complex tuple returns (e.g., `RFC5424Header`).

## Key Constants & Thresholds
- **Similarity Threshold**: 0.5 (50% token match required to merge into a template).
- **Template Variable Marker**: `<*>`.
- **Batch Size**: Default chunking/flushing occurs every 10 messages (configurable in `main.rs`).

## Test Requirements
- **Unit Tests**: Every parser and storage logic change must include tests in the file's `mod tests` block.
- **Integration Tests**: Full-pipeline tests reside in `tests/integration_test.rs`. Verify end-to-end functionality using the `sankshepa` binary.
