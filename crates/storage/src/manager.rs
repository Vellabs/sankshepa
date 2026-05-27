use crate::backend::{LocalBackend, StorageBackend};
use crate::logshrink::LogChunk;
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    // Flag to prevent concurrent retention runs
    retention_running: Arc<AtomicBool>,
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
            if base_path
                .extension()
                .map(|e| e != "lshrink")
                .unwrap_or(true)
            {
                let _ = fs::create_dir_all(&base_path);
            } else if let Some(parent) = base_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                let _ = fs::create_dir_all(parent);
            }
        }

        Self {
            base_path,
            max_size_bytes,
            retention_hours,
            backend,
            retention_running: Arc::new(AtomicBool::new(false)),
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
        if self
            .base_path
            .extension()
            .is_some_and(|ext| ext == "lshrink")
        {
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
    /// Uses a flag to prevent concurrent runs and avoid spawning unbounded threads
    pub fn enforce_retention(&self) {
        // Check if retention is already running; if so, skip this call
        if self.retention_running.swap(true, Ordering::Acquire) {
            return; // Already running
        }

        let base = self.base_path.clone();
        let retention = self.retention_hours;
        let max_size = self.max_size_bytes;
        let flag = self.retention_running.clone();

        // Run in background to avoid blocking write
        std::thread::spawn(move || {
            Self::rotate(base, retention, max_size);
            flag.store(false, Ordering::Release);
        });
    }

    fn rotate(base_path: PathBuf, retention_hours: u64, max_size_bytes: u64) {
        let _now = Utc::now();
        let mut files = Vec::new();
        let mut _total_size = 0u64;

        // Traverse directories
        if let Ok(entries) = fs::read_dir(&base_path) {
            for entry in entries.flatten() {
                if entry.file_type().map(|f| f.is_dir()).unwrap_or(false) {
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
                if let Ok(chunks) = fs::read_dir(entry.path()) {
                    for chunk in chunks.flatten() {
                        results.push(chunk.path());
                    }
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logshrink::LogChunk;
    use chrono::Utc;
    use sankshepa_protocol::SyslogMessage;

    fn make_msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 13,
            facility: 1,
            severity: 5,
            timestamp: Some(Utc::now()),
            hostname: Some("host".to_string()),
            app_name: None,
            procid: None,
            msgid: None,
            structured_data: None,
            message: text.to_string(),
            is_rfc5424: false,
            node_id: None,
        }
    }

    fn make_chunk_with_msg(text: &str) -> LogChunk {
        let mut chunk = LogChunk::new();
        chunk.add_message(make_msg(text));
        chunk.finish_and_process();
        chunk
    }

    #[test]
    fn test_write_chunk_to_lshrink_file() {
        let path = format!("/tmp/mgr_direct_{}.lshrink", std::process::id());
        let mgr = StorageManager::new(&path, 1024 * 1024, 24);
        let chunk = make_chunk_with_msg("Direct file write");

        let size = mgr.write_chunk(chunk).unwrap();
        assert!(size > 0);
        assert!(std::path::Path::new(&path).exists());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_write_chunk_to_directory_creates_bucket() {
        let dir = format!("/tmp/mgr_dir_{}", std::process::id());
        let mgr = StorageManager::new(&dir, 1024 * 1024 * 10, 24);
        let chunk = make_chunk_with_msg("Bucketed write");

        mgr.write_chunk(chunk).unwrap();

        // Wait briefly for retention thread to finish (it shouldn't affect directories)
        std::thread::sleep(std::time::Duration::from_millis(50));

        let subdirs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .collect();
        assert!(
            !subdirs.is_empty(),
            "Expected at least one time-bucketed subdirectory"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_empty_chunk_is_not_written() {
        let path = format!("/tmp/mgr_empty_{}.lshrink", std::process::id());
        let mgr = StorageManager::new(&path, 1024 * 1024, 24);

        // Chunk with no records
        let mut chunk = LogChunk::new();
        chunk.finish_and_process();

        let size = mgr.write_chunk(chunk).unwrap();
        assert_eq!(size, 0);

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn test_query_all_finds_written_chunks() {
        let dir = format!("/tmp/mgr_query_{}", std::process::id());
        let mgr = StorageManager::new(&dir, 1024 * 1024 * 10, 24);

        mgr.write_chunk(make_chunk_with_msg("First chunk")).unwrap();
        mgr.write_chunk(make_chunk_with_msg("Second chunk"))
            .unwrap();

        // Give retention a moment to settle
        std::thread::sleep(std::time::Duration::from_millis(100));

        let paths = mgr.query_all();
        assert!(
            paths.len() >= 2,
            "Expected at least 2 chunk files, found {}",
            paths.len()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_enforce_retention_flag_prevents_concurrent_runs() {
        let dir = format!("/tmp/mgr_retention_{}", std::process::id());
        let mgr = StorageManager::new(&dir, 1024 * 1024 * 10, 24);

        // Trigger retention twice rapidly; flag should prevent a second thread launch
        mgr.enforce_retention();
        mgr.enforce_retention(); // Second call should be a no-op

        std::thread::sleep(std::time::Duration::from_millis(200));

        // Flag should be cleared after first run completes
        assert!(
            !mgr.retention_running
                .load(std::sync::atomic::Ordering::Relaxed),
            "Retention flag should be cleared after run completes"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
