# LogShrink Storage Layer

Sankshepa implements a high-performance, columnar storage layer based on the **LogShrink** methodology. This approach dramatically reduces the storage footprint of syslog data by deduplicating repetitive log patterns into templates and storing dynamic variables separately.

## 1. LogShrink Engine

The core of the storage layer is the `LogChunk` processor, which transforms raw `SyslogMessage` objects into structured `LogRecord` entries.

### Template Extraction
1. **Grouping**: Logs are first grouped by their token count (word count). Similarity is only calculated between logs of the same length to optimize performance.
2. **Similarity Clustering**: Within each group, logs are compared using a similarity threshold (default: 0.5). If two logs share many identical tokens in the same positions, they are considered candidates for a template.
3. **Template Generation**: Static tokens are preserved, while differing tokens are replaced with a `<*>` variable marker. 
    - *Example*: `User alice failed login` and `User bob failed login` become `User <*> failed login`.
4. **Variable Extraction**: The specific values that replaced the `<*>` markers (e.g., `alice`, `bob`) are stored as an ordered list of variables for that specific record.

### String Interning
To further save space, recurring metadata strings like `hostname`, `app_name`, `procid`, and `msgid` are stored in a global **String Pool** within each chunk. Records store a 32-bit integer ID referencing these strings instead of the full text.

## 2. Columnar Storage

Once a chunk is processed (typically every 10-1000 messages), it is serialized using a columnar format.

### Organization
Instead of storing records as a list of structs (Row-major), Sankshepa splits each field into its own contiguous block (Column-major):
- `timestamp_block`: Unix timestamps (milliseconds).
- `priority_block`: Syslog priority values.
- `hostname_id_block`, `app_name_id_block`, etc.: References to the string pool.
- `template_id_block`: References to the deduced patterns.
- `variable_block`: The dynamic data extracted from the logs.

### Compression
1. **Serialization**: The columnar blocks are serialized using `postcard`.
2. **Block Compression**: Each block (and the final `CompressedChunk` structure) is compressed using **zstd**. Columnar data compresses significantly better than row-major data because values in the same column often share similar characteristics (e.g., repeating hostnames or monotonically increasing timestamps).

## 3. Storage Efficiency

By combining template extraction with columnar compression, Sankshepa typically achieves:
- **10x - 20x reduction** for heterogeneous logs.
- **50x+ reduction** for highly repetitive logs (e.g., heartbeat or firewall logs).

## 4. Query & Reconstruction

When querying a `.lshrink` file:
1. The `CompressedChunk` is decompressed using `zstd`.
2. The `postcard` blocks are deserialized.
3. For each record, the original message is reconstructed by:
    - Retrieving the template pattern for the `template_id`.
    - Iteratively replacing each `<*>` marker with the corresponding value from the record's `variables` list.
    - Resolving internal string IDs back to their original values via the `string_pool`.
