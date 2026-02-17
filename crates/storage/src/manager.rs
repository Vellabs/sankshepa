use crate::backend::{LocalBackend, StorageBackend};
use crate::logshrink::LogChunk;
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::info;

/// Manages log storage with time-based bucketing and retention
pub struct StorageManager {
    base_path: PathBuf,
    // Max total size in bytes
    max_size_bytes: u64,
    // Retention period in hours
    retention_hours: u64,
    backend: Box<dyn StorageBackend>,
}

impl StorageManager {
    pub fn new(base_path: impl Into<PathBuf>, max_size_bytes: u64, retention_hours: u64) -> Self {
        Self::new_with_backend(
            base_path,
            max_size_bytes,
            retention_hours,
            Box::new(LocalBackend),
        )
    }

    pub fn new_with_backend(
        base_path: impl Into<PathBuf>,
        max_size_bytes: u64,
        retention_hours: u64,
        backend: Box<dyn StorageBackend>,
    ) -> Self {
        let base_path = base_path.into();

        // If it's a directory path (not ending in .lshrink), create it.
        // If it's a file path, create its parent.
        if !base_path.as_os_str().is_empty() {
            if base_path.extension().map(|e| e != "lshrink").unwrap_or(true) {
                let _ = fs::create_dir_all(&base_path);
            } else if let Some(parent) = base_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = fs::create_dir_all(parent);
                }
            }
        }

        Self {
            base_path,
            max_size_bytes,
            retention_hours,
            backend,
        }
    }

    /// Generates a bucket filename based on timestamp (Hourly)
    fn get_bucket_dir(&self, timestamp: i64) -> PathBuf {
        let dt = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
        self.base_path.join(format!(
            "{:04}-{:02}-{:02}_{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour()
        ))
    }

    /// Writes a chunk to the appropriate time bucket.
    pub fn write_chunk(&self, chunk: LogChunk) -> anyhow::Result<u64> {
        if chunk.records.is_empty() {
            return Ok(0);
        }

        // If base_path looks like a file, write directly to it (for tests/benchmarks)
        if self.base_path.extension().is_some_and(|ext| ext == "lshrink") {
            return self.backend.save_chunk(chunk, &self.base_path);
        }

        let timestamp = chunk.records[0].timestamp / 1000;
        let bucket_dir = self.get_bucket_dir(timestamp);

        self.backend.create_dir(&bucket_dir)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let chunk_filename = format!("chunk_{}_{}_{}.lshrink", timestamp, std::process::id(), now);
        let full_path = bucket_dir.join(chunk_filename);

        let size = self.backend.save_chunk(chunk, &full_path)?;

        self.enforce_retention();
        Ok(size)
    }

    /// Enforce retention properties (size and age)
    pub fn enforce_retention(&self) {
        let base = self.base_path.clone();
        let retention = self.retention_hours;
        let max_size = self.max_size_bytes;

        // Run in background to avoid blocking write
        std::thread::spawn(move || {
            Self::rotate(base, retention, max_size);
        });
    }

    fn rotate(base_path: PathBuf, retention_hours: u64, max_size_bytes: u64) {
        let _now = Utc::now();
        let mut files = Vec::new();
        let mut _total_size = 0u64;

        // Traverse directories
        if let Ok(entries) = fs::read_dir(&base_path) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        // Check if directory matches timestamp pattern
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        // simplistic check
                        if name_str.contains('_') {
                            // Recursively check files
                            if let Ok(chunk_entries) = fs::read_dir(entry.path()) {
                                for chunk in chunk_entries.flatten() {
                                    if let Ok(meta) = chunk.metadata() {
                                        _total_size += meta.len();
                                        files.push((
                                            chunk.path(),
                                            meta.modified().unwrap_or(SystemTime::now()),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 1. Time-based retention
        // We actually need to parse the folder name for time, but using file mod time is a safe fallback.
        let cutoff = SystemTime::now() - std::time::Duration::from_secs(retention_hours * 3600);

        files.sort_by_key(|k| k.1); // Oldest first

        // Remove old files
        let mut active_files = Vec::new();
        for (path, modified) in files {
            if modified < cutoff {
                info!("Rotating old log file: {:?}", path);
                let _ = fs::remove_file(path);
            } else {
                active_files.push((path, modified));
            }
        }

        // 2. Size-based retention (Delete oldest if over quota)
        // Recalculate size isn't needed if we subtract deleted, but let's just process active_files
        let mut current_size: u64 = active_files
            .iter()
            .map(|(p, _)| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
            .sum();

        if current_size > max_size_bytes {
            // active_files is sorted oldest to newest
            for (path, _) in active_files {
                if current_size <= max_size_bytes {
                    break;
                }
                if let Ok(meta) = fs::metadata(&path) {
                    let len = meta.len();
                    info!("Rotating log file due to quota: {:?}", path);
                    if fs::remove_file(&path).is_ok() {
                        current_size -= len;
                    }
                }
            }
        }

        // Clean empty directories
        if let Ok(entries) = fs::read_dir(&base_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let _ = fs::remove_dir(entry.path()); // Fails if not empty, which is what we want
                }
            }
        }
    }

    pub fn query_all(&self) -> Vec<PathBuf> {
        let mut results = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Ok(chunks) = fs::read_dir(entry.path()) {
                        for chunk in chunks.flatten() {
                            results.push(chunk.path());
                        }
                    }
                }
            }
        }
        results
    }
}
