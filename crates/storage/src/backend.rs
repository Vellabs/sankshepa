use crate::StorageEngine;
use crate::logshrink::LogChunk;
use std::fs;
use std::path::{Path, PathBuf};

/// Trait for pluggable storage backends
pub trait StorageBackend: Send + Sync {
    /// Save a chunk to the backend
    fn save_chunk(&self, chunk: LogChunk, path: &Path) -> anyhow::Result<u64>;

    /// Load a chunk from the backend
    fn load_chunk(&self, path: &Path) -> anyhow::Result<LogChunk>;

    /// Create directory structure if needed
    fn create_dir(&self, path: &Path) -> anyhow::Result<()>;
}

/// Local filesystem storage backend
pub struct LocalBackend;

impl StorageBackend for LocalBackend {
    fn save_chunk(&self, chunk: LogChunk, path: &Path) -> anyhow::Result<u64> {
        StorageEngine::save_chunk(
            chunk,
            path.to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
        )
    }

    fn load_chunk(&self, path: &Path) -> anyhow::Result<LogChunk> {
        StorageEngine::load_chunk(
            path.to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
        )
    }

    fn create_dir(&self, path: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(path)?;
        Ok(())
    }
}

/// Mock cloud storage backend for testing
pub struct MockCloudBackend {
    pub root: PathBuf,
}

impl StorageBackend for MockCloudBackend {
    fn save_chunk(&self, chunk: LogChunk, path: &Path) -> anyhow::Result<u64> {
        let full_path = self.root.join(path);
        // Ensure parent exists
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        StorageEngine::save_chunk(
            chunk,
            full_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
        )
    }

    fn load_chunk(&self, path: &Path) -> anyhow::Result<LogChunk> {
        let full_path = self.root.join(path);
        StorageEngine::load_chunk(
            full_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
        )
    }

    fn create_dir(&self, path: &Path) -> anyhow::Result<()> {
        let full_path = self.root.join(path);
        fs::create_dir_all(full_path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sankshepa_protocol::SyslogMessage;

    fn make_msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 34,
            facility: 4,
            severity: 2,
            timestamp: Some(Utc::now()),
            hostname: Some("host".to_string()),
            app_name: Some("app".to_string()),
            procid: None,
            msgid: None,
            structured_data: None,
            message: text.to_string(),
            is_rfc5424: false,
            node_id: None,
        }
    }

    #[test]
    fn test_mock_cloud_backend_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("mock_cloud_{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();

        let backend = MockCloudBackend { root: tmp.clone() };

        let mut chunk = LogChunk::new();
        chunk.add_message(make_msg("Connection established"));
        chunk.finish_and_process();

        let rel_path = Path::new("chunk_test.lshrink");
        backend.save_chunk(chunk, rel_path).unwrap();

        let loaded = backend.load_chunk(rel_path).unwrap();
        assert_eq!(loaded.records.len(), 1);
        let hostname = loaded.records[0]
            .hostname_id
            .and_then(|id| loaded.string_pool.get(id as usize))
            .unwrap();
        assert_eq!(hostname, "host");

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_local_backend_save_load_roundtrip() {
        let path =
            std::env::temp_dir().join(format!("local_backend_{}.lshrink", std::process::id()));
        let backend = LocalBackend;

        let mut chunk = LogChunk::new();
        chunk.add_message(make_msg("Disk full warning"));
        chunk.finish_and_process();

        backend.save_chunk(chunk, &path).unwrap();
        let loaded = backend.load_chunk(&path).unwrap();
        assert_eq!(loaded.records.len(), 1);

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_mock_cloud_backend_create_dir() {
        let tmp = std::env::temp_dir().join(format!("mock_dir_{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();

        let backend = MockCloudBackend { root: tmp.clone() };
        let sub = Path::new("sub/nested");
        backend.create_dir(sub).unwrap();

        assert!(tmp.join(sub).is_dir());
        fs::remove_dir_all(&tmp).unwrap();
    }
}
