//! Anti-Entropy Protocol for AP consistency.
//!
//! This module implements periodic synchronization between nodes
//! using Merkle trees to efficiently detect and resolve differences.

use crate::merkle_tree::{MerkleDigest, MerkleTree};
use crate::replication_log::{LogEntry, ReplicationLog, ReplicationOp};
use crate::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Anti-entropy sync state for a node.
pub struct AntiEntropyState {
    /// Node ID
    node_id: String,
    /// Merkle tree for template state
    template_tree: MerkleTree,
    /// Last known vector clocks from peers
    peer_clocks: HashMap<String, VectorClock>,
    /// Replication log reference
    log: Arc<RwLock<ReplicationLog>>,
    /// Template to hash mapping for Merkle tree
    template_hashes: HashMap<String, u64>,
}

/// Messages for anti-entropy protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AntiEntropyMessage {
    /// Request sync with digest
    SyncRequest {
        from_node: String,
        merkle_digest: MerkleDigest,
        vector_clock: VectorClock,
    },
    /// Response with missing entries
    SyncResponse {
        from_node: String,
        entries: Vec<LogEntry>,
        merkle_digest: MerkleDigest,
    },
    /// Request specific entries for differing buckets
    BucketRequest {
        from_node: String,
        buckets: Vec<usize>,
        vector_clock: VectorClock,
    },
    /// Response with entries for specific buckets
    BucketResponse {
        from_node: String,
        entries: Vec<LogEntry>,
    },
}

impl AntiEntropyState {
    /// Create new anti-entropy state.
    pub fn new(node_id: String, log: Arc<RwLock<ReplicationLog>>) -> Self {
        Self {
            node_id,
            template_tree: MerkleTree::new(8), // 256 buckets
            peer_clocks: HashMap::new(),
            log,
            template_hashes: HashMap::new(),
        }
    }

    /// Add a template to the Merkle tree.
    pub fn add_template(&mut self, pattern: &str, template_id: u32) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        pattern.hash(&mut hasher);
        template_id.hash(&mut hasher);
        let hash = hasher.finish();

        self.template_tree.insert(pattern, hash);
        self.template_hashes.insert(pattern.to_string(), hash);
    }

    /// Generate a sync request.
    pub async fn generate_sync_request(&self) -> AntiEntropyMessage {
        let log = self.log.read().await;
        AntiEntropyMessage::SyncRequest {
            from_node: self.node_id.clone(),
            merkle_digest: self.template_tree.digest(),
            vector_clock: log.current_clock().clone(),
        }
    }

    /// Handle an incoming sync request.
    pub async fn handle_sync_request(
        &mut self,
        request: AntiEntropyMessage,
    ) -> Option<AntiEntropyMessage> {
        if let AntiEntropyMessage::SyncRequest {
            from_node,
            merkle_digest,
            vector_clock,
        } = request
        {
            // Find differing buckets
            let diff_buckets = self.template_tree.diff_with_digest(&merkle_digest);

            if diff_buckets.is_empty() && !self.has_new_entries(&vector_clock).await {
                debug!("No differences with {}", from_node);
                return None;
            }

            // Get entries they don't have
            let log = self.log.read().await;
            let entries = log.entries_after_clock(&vector_clock);

            // Update peer clock
            self.peer_clocks.insert(from_node.clone(), vector_clock);

            info!(
                "Sending {} entries to {} (diff buckets: {:?})",
                entries.len(),
                from_node,
                diff_buckets
            );

            Some(AntiEntropyMessage::SyncResponse {
                from_node: self.node_id.clone(),
                entries,
                merkle_digest: self.template_tree.digest(),
            })
        } else {
            None
        }
    }

    /// Handle an incoming sync response.
    pub async fn handle_sync_response(&mut self, response: AntiEntropyMessage) -> usize {
        if let AntiEntropyMessage::SyncResponse {
            from_node,
            entries,
            merkle_digest: _,
        } = response
        {
            if entries.is_empty() {
                debug!("No new entries from {}", from_node);
                return 0;
            }

            let applied = {
                let mut log = self.log.write().await;
                log.replicate(entries.clone())
            };

            // Update Merkle tree with new templates
            for entry in &entries {
                if let ReplicationOp::NewTemplate {
                    ref pattern,
                    template_id,
                } = entry.operation
                {
                    self.add_template(pattern, template_id);
                }
            }

            info!("Applied {} entries from {}", applied, from_node);
            applied
        } else {
            0
        }
    }

    /// Check if we have entries newer than the given clock.
    async fn has_new_entries(&self, clock: &VectorClock) -> bool {
        let log = self.log.read().await;
        !log.entries_after_clock(clock).is_empty()
    }

    /// Get current Merkle digest.
    pub fn get_digest(&self) -> MerkleDigest {
        self.template_tree.digest()
    }

    /// Get peer vector clocks.
    pub fn peer_clocks(&self) -> &HashMap<String, VectorClock> {
        &self.peer_clocks
    }
}

/// Anti-entropy sync manager that runs periodic synchronization.
pub struct AntiEntropyManager {
    state: Arc<RwLock<AntiEntropyState>>,
    sync_interval_secs: u64,
}

impl AntiEntropyManager {
    /// Create a new anti-entropy manager.
    pub fn new(state: Arc<RwLock<AntiEntropyState>>, sync_interval_secs: u64) -> Self {
        Self {
            state,
            sync_interval_secs,
        }
    }

    /// Get the state reference.
    pub fn state(&self) -> Arc<RwLock<AntiEntropyState>> {
        self.state.clone()
    }

    /// Get sync interval.
    pub fn sync_interval(&self) -> u64 {
        self.sync_interval_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_request_generation() {
        let log = Arc::new(RwLock::new(ReplicationLog::new("node1".to_string())));
        let state = AntiEntropyState::new("node1".to_string(), log);

        let request = state.generate_sync_request().await;
        match request {
            AntiEntropyMessage::SyncRequest { from_node, .. } => {
                assert_eq!(from_node, "node1");
            }
            _ => panic!("Expected SyncRequest"),
        }
    }

    #[tokio::test]
    async fn test_template_sync() {
        let log1 = Arc::new(RwLock::new(ReplicationLog::new("node1".to_string())));
        let log2 = Arc::new(RwLock::new(ReplicationLog::new("node2".to_string())));

        let mut state1 = AntiEntropyState::new("node1".to_string(), log1.clone());
        let mut state2 = AntiEntropyState::new("node2".to_string(), log2.clone());

        // Add template to node1
        {
            let mut log = log1.write().await;
            log.append(ReplicationOp::NewTemplate {
                pattern: "Test <*>".to_string(),
                template_id: 1,
            });
        }
        state1.add_template("Test <*>", 1);

        // Sync from node1 to node2
        let request = state1.generate_sync_request().await;
        let response = state2.handle_sync_request(request).await;

        assert!(response.is_some());

        // Node1 processes response from node2
        if let Some(resp) = response {
            let applied = state1.handle_sync_response(resp).await;
            // Node2 sends back its entries (none in this case as node2 was empty)
            assert_eq!(applied, 0);
        }
    }
}
