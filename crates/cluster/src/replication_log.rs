//! Replication Log (Op-Log) for AP system consistency.
//!
//! This module implements an append-only operation log that captures all
//! template and variable mutations. It enables:
//! - Durable operation history for crash recovery
//! - Anti-entropy sync between nodes
//! - Eventual consistency through log exchange

use crate::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Operation types that can be replicated across the cluster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ReplicationOp {
    /// A new template was discovered
    NewTemplate { pattern: String, template_id: u32 },
    /// Variables associated with a template instance
    TemplateVariables {
        template_id: u32,
        variables: Vec<String>,
        timestamp_ms: i64,
    },
    /// Template merge (when two similar templates converge)
    MergeTemplates {
        source_id: u32,
        target_id: u32,
        merged_pattern: String,
    },
}

/// A log entry with metadata for replication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unique entry ID (monotonic within a node)
    pub sequence: u64,
    /// Node that originated this operation
    pub origin_node: String,
    /// Vector clock at time of operation
    pub vector_clock: VectorClock,
    /// Wall clock timestamp (for display/debugging)
    pub wall_time_ms: i64,
    /// The actual operation
    pub operation: ReplicationOp,
    /// Hash of the operation for deduplication
    pub op_hash: u64,
}

impl LogEntry {
    /// Create a new log entry.
    pub fn new(
        sequence: u64,
        origin_node: String,
        vector_clock: VectorClock,
        operation: ReplicationOp,
    ) -> Self {
        let wall_time_ms = chrono::Utc::now().timestamp_millis();
        let op_hash = Self::compute_hash(&operation);
        Self {
            sequence,
            origin_node,
            vector_clock,
            wall_time_ms,
            operation,
            op_hash,
        }
    }

    fn compute_hash(op: &ReplicationOp) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        // Hash based on operation type and key fields
        match op {
            ReplicationOp::NewTemplate { pattern, .. } => {
                "new_template".hash(&mut hasher);
                pattern.hash(&mut hasher);
            }
            ReplicationOp::TemplateVariables {
                template_id,
                variables,
                timestamp_ms,
            } => {
                "template_vars".hash(&mut hasher);
                template_id.hash(&mut hasher);
                variables.hash(&mut hasher);
                timestamp_ms.hash(&mut hasher);
            }
            ReplicationOp::MergeTemplates {
                source_id,
                target_id,
                ..
            } => {
                "merge".hash(&mut hasher);
                source_id.hash(&mut hasher);
                target_id.hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}

/// The replication log maintains the operation history.
pub struct ReplicationLog {
    /// Node ID for this log
    node_id: String,
    /// All log entries (in memory, also persisted)
    entries: Vec<LogEntry>,
    /// Current sequence number
    sequence: AtomicU64,
    /// Current vector clock
    vector_clock: VectorClock,
    /// Set of operation hashes for deduplication
    seen_ops: HashSet<u64>,
    /// Index: template pattern -> entry index
    template_index: HashMap<String, usize>,
    /// Optional file writer for persistence
    log_file: Option<BufWriter<File>>,
}

impl ReplicationLog {
    /// Create a new replication log.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            entries: Vec::new(),
            sequence: AtomicU64::new(0),
            vector_clock: VectorClock::new(),
            seen_ops: HashSet::new(),
            template_index: HashMap::new(),
            log_file: None,
        }
    }

    /// Create a replication log with persistence.
    pub fn with_persistence<P: AsRef<Path>>(node_id: String, path: P) -> anyhow::Result<Self> {
        let mut log = Self::new(node_id);

        // Load existing entries if file exists
        if path.as_ref().exists() {
            log.load_from_file(&path)?;
        }

        // Open file for appending
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        log.log_file = Some(BufWriter::new(file));

        Ok(log)
    }

    /// Load entries from a log file.
    fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if let Ok(entry) = serde_json::from_str::<LogEntry>(&line) {
                self.apply_entry(entry);
            }
        }

        Ok(())
    }

    /// Append a new operation to the log.
    pub fn append(&mut self, operation: ReplicationOp) -> LogEntry {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        self.vector_clock.increment(&self.node_id);

        let entry = LogEntry::new(
            seq,
            self.node_id.clone(),
            self.vector_clock.clone(),
            operation,
        );

        self.apply_entry(entry.clone());

        // Persist to disk if configured
        if let Some(ref mut writer) = self.log_file
            && let Ok(json) = serde_json::to_string(&entry)
        {
            let _ = writeln!(writer, "{}", json);
            let _ = writer.flush();
        }

        entry
    }

    /// Apply an entry (either local or from replication).
    fn apply_entry(&mut self, entry: LogEntry) {
        // Deduplication check
        if self.seen_ops.contains(&entry.op_hash) {
            return;
        }

        // Update vector clock
        self.vector_clock.merge(&entry.vector_clock);

        // Update sequence if needed
        let current_seq = self.sequence.load(Ordering::SeqCst);
        if entry.sequence >= current_seq {
            self.sequence.store(entry.sequence + 1, Ordering::SeqCst);
        }

        // Index by pattern if it's a template
        if let ReplicationOp::NewTemplate { ref pattern, .. } = entry.operation {
            self.template_index
                .insert(pattern.clone(), self.entries.len());
        }

        self.seen_ops.insert(entry.op_hash);
        self.entries.push(entry);
    }

    /// Replicate entries from another node.
    pub fn replicate(&mut self, entries: Vec<LogEntry>) -> usize {
        let mut applied = 0;
        for entry in entries {
            if !self.seen_ops.contains(&entry.op_hash) {
                self.apply_entry(entry.clone());

                // Persist replicated entries
                if let Some(ref mut writer) = self.log_file
                    && let Ok(json) = serde_json::to_string(&entry)
                {
                    let _ = writeln!(writer, "{}", json);
                }

                applied += 1;
            }
        }

        if let Some(ref mut writer) = self.log_file {
            let _ = writer.flush();
        }

        applied
    }

    /// Get entries after a given sequence number for a specific node.
    pub fn entries_after(&self, node_id: &str, after_seq: u64) -> Vec<LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.origin_node == node_id && e.sequence > after_seq)
            .cloned()
            .collect()
    }

    /// Get all entries after a given vector clock (for anti-entropy).
    pub fn entries_after_clock(&self, clock: &VectorClock) -> Vec<LogEntry> {
        self.entries
            .iter()
            .filter(|e| {
                let their_ts = clock.get(&e.origin_node);
                e.sequence > their_ts
            })
            .cloned()
            .collect()
    }

    /// Get all entries (for full sync).
    pub fn all_entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Get current vector clock.
    pub fn current_clock(&self) -> &VectorClock {
        &self.vector_clock
    }

    /// Get all template patterns from the log.
    pub fn get_templates(&self) -> Vec<(String, u32)> {
        self.entries
            .iter()
            .filter_map(|e| {
                if let ReplicationOp::NewTemplate {
                    ref pattern,
                    template_id,
                } = e.operation
                {
                    Some((pattern.clone(), template_id))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if a template pattern exists.
    pub fn has_template(&self, pattern: &str) -> bool {
        self.template_index.contains_key(pattern)
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_retrieve() {
        let mut log = ReplicationLog::new("node1".to_string());

        let op = ReplicationOp::NewTemplate {
            pattern: "User <*> logged in".to_string(),
            template_id: 1,
        };

        let entry = log.append(op);
        assert_eq!(entry.sequence, 0);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_deduplication() {
        let mut log = ReplicationLog::new("node1".to_string());

        let op = ReplicationOp::NewTemplate {
            pattern: "User <*> logged in".to_string(),
            template_id: 1,
        };

        let entry = log.append(op.clone());

        // Try to replicate the same entry
        log.replicate(vec![entry]);

        // Should still have only one entry
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_replication() {
        let mut log1 = ReplicationLog::new("node1".to_string());
        let mut log2 = ReplicationLog::new("node2".to_string());

        let op1 = ReplicationOp::NewTemplate {
            pattern: "Pattern A".to_string(),
            template_id: 1,
        };
        let entry1 = log1.append(op1);

        let op2 = ReplicationOp::NewTemplate {
            pattern: "Pattern B".to_string(),
            template_id: 2,
        };
        let entry2 = log2.append(op2);

        // Replicate between logs
        log1.replicate(vec![entry2.clone()]);
        log2.replicate(vec![entry1.clone()]);

        assert_eq!(log1.len(), 2);
        assert_eq!(log2.len(), 2);
    }

    #[test]
    fn test_persistence_save_and_reload() {
        let path = std::env::temp_dir()
            .join(format!("replog_{}.jsonl", std::process::id()))
            .to_string_lossy()
            .into_owned();

        {
            let mut log = ReplicationLog::with_persistence("node1".to_string(), &path).unwrap();
            log.append(ReplicationOp::NewTemplate {
                pattern: "Error: <*>".to_string(),
                template_id: 10,
            });
            log.append(ReplicationOp::TemplateVariables {
                template_id: 10,
                variables: vec!["disk full".to_string()],
                timestamp_ms: 1_700_000_000_000,
            });
        }

        // Reload from disk
        let reloaded = ReplicationLog::with_persistence("node1".to_string(), &path).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.has_template("Error: <*>"));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_get_templates() {
        let mut log = ReplicationLog::new("node1".to_string());
        log.append(ReplicationOp::NewTemplate {
            pattern: "Login <*>".to_string(),
            template_id: 1,
        });
        log.append(ReplicationOp::NewTemplate {
            pattern: "Logout <*>".to_string(),
            template_id: 2,
        });
        log.append(ReplicationOp::TemplateVariables {
            template_id: 1,
            variables: vec!["alice".to_string()],
            timestamp_ms: 0,
        });

        let templates = log.get_templates();
        assert_eq!(templates.len(), 2);
        let patterns: Vec<String> = templates.into_iter().map(|(p, _)| p).collect();
        assert!(patterns.contains(&"Login <*>".to_string()));
        assert!(patterns.contains(&"Logout <*>".to_string()));
    }

    #[test]
    fn test_has_template() {
        let mut log = ReplicationLog::new("node1".to_string());
        assert!(!log.has_template("User <*> logged in"));

        log.append(ReplicationOp::NewTemplate {
            pattern: "User <*> logged in".to_string(),
            template_id: 1,
        });

        assert!(log.has_template("User <*> logged in"));
    }

    #[test]
    fn test_entries_after_sequence() {
        let mut log = ReplicationLog::new("node1".to_string());
        log.append(ReplicationOp::NewTemplate {
            pattern: "Pattern A".to_string(),
            template_id: 1,
        });
        log.append(ReplicationOp::NewTemplate {
            pattern: "Pattern B".to_string(),
            template_id: 2,
        });

        let after_first = log.entries_after("node1", 0);
        assert_eq!(after_first.len(), 1); // Only sequence 1 is > 0
    }

    #[test]
    fn test_vector_clock_updated_on_append() {
        let mut log = ReplicationLog::new("node1".to_string());
        assert_eq!(log.current_clock().get("node1"), 0);

        log.append(ReplicationOp::NewTemplate {
            pattern: "P".to_string(),
            template_id: 0,
        });
        assert_eq!(log.current_clock().get("node1"), 1);
    }

    #[test]
    fn test_node_id() {
        let log = ReplicationLog::new("my-node".to_string());
        assert_eq!(log.node_id(), "my-node");
    }

    #[test]
    fn test_is_empty_initially() {
        let log = ReplicationLog::new("node1".to_string());
        assert!(log.is_empty());
    }
}
