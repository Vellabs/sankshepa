use std::path::{Path, PathBuf};
use std::fs;
use crate::logshrink::LogChunk;
use crate::StorageEngine;

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
        StorageEngine::save_chunk(chunk, path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?)
    }

    fn load_chunk(&self, path: &Path) -> anyhow::Result<LogChunk> {
        StorageEngine::load_chunk(path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?)
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
        StorageEngine::save_chunk(chunk, full_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?)
    }

    fn load_chunk(&self, path: &Path) -> anyhow::Result<LogChunk> {
        let full_path = self.root.join(path);
        StorageEngine::load_chunk(full_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?)
    }

    fn create_dir(&self, path: &Path) -> anyhow::Result<()> {
        let full_path = self.root.join(path);
        fs::create_dir_all(full_path)?;
        Ok(())
    }
}
