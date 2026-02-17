//! Gossip Protocol implementation for AP cluster communication.
//!
//! This module implements an enhanced gossip protocol that leverages
//! the replication log and CRDTs for reliable template synchronization.

use crate::PeerInfo;
use crate::anti_entropy::{AntiEntropyMessage, AntiEntropyState};
use crate::crdt::CRDTTemplateStore;
use crate::replication_log::{LogEntry, ReplicationLog, ReplicationOp};
use crate::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast, mpsc};
use tracing::{debug, info};

/// Type alias for the template request receiver
pub type TemplateRx = mpsc::Receiver<(String, tokio::sync::oneshot::Sender<u32>)>;

/// Extended cluster message types for AP replication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationMessage {
    /// Standard heartbeat with extended metadata
    Heartbeat {
        node_id: String,
        vector_clock: VectorClock,
        template_count: u32,
        log_length: usize,
    },
    /// New template notification with full entry
    NewTemplate { entry: LogEntry },
    /// Request log entries after a vector clock
    PullRequest {
        from_node: String,
        vector_clock: VectorClock,
    },
    /// Response with log entries
    PullResponse { entries: Vec<LogEntry> },
    /// Full state sync request
    FullSyncRequest { from_node: String },
    /// Full state response with CRDT store
    FullSyncResponse {
        from_node: String,
        log_entries: Vec<LogEntry>,
        crdt_state: Vec<u8>, // Serialized CRDTTemplateStore
    },
    /// Anti-entropy message wrapper
    AntiEntropy(AntiEntropyMessage),
    /// Ack for received entries
    Ack { from_node: String, last_seq: u64 },
}

/// Configuration for the gossip protocol.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Anti-entropy sync interval in seconds
    pub sync_interval_secs: u64,
    /// Peer timeout in seconds
    pub peer_timeout_secs: i64,
    /// Maximum entries per pull response
    pub max_entries_per_pull: usize,
    /// Fanout for gossip (number of peers to send to)
    pub gossip_fanout: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 5,
            sync_interval_secs: 30,
            peer_timeout_secs: 30,
            max_entries_per_pull: 100,
            gossip_fanout: 3,
        }
    }
}

/// Gossip protocol manager for AP replication.
pub struct GossipManager {
    /// Node ID
    node_id: String,
    /// Configuration
    config: GossipConfig,
    /// Replication log
    log: Arc<RwLock<ReplicationLog>>,
    /// CRDT template store
    template_store: Arc<RwLock<CRDTTemplateStore>>,
    /// Anti-entropy state
    anti_entropy: Arc<RwLock<AntiEntropyState>>,
    /// Known peers
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    /// Peer vector clocks
    peer_clocks: Arc<RwLock<HashMap<String, VectorClock>>>,
    /// Template notification sender
    template_tx: mpsc::Sender<(String, tokio::sync::oneshot::Sender<u32>)>,
    /// External broadcast for new templates
    ext_template_tx: broadcast::Sender<(u32, String)>,
    /// External broadcast for incoming logs (template_id, variables, timestamp)
    ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
}

impl GossipManager {
    /// Create a new gossip manager.
    pub fn new(
        node_id: String,
        config: GossipConfig,
        ext_template_tx: broadcast::Sender<(u32, String)>,
        ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
    ) -> (Self, TemplateRx) {
        let (template_tx, template_rx) = mpsc::channel(100);
        let log = Arc::new(RwLock::new(ReplicationLog::new(node_id.clone())));
        let template_store = Arc::new(RwLock::new(CRDTTemplateStore::new(node_id.clone())));
        let anti_entropy = Arc::new(RwLock::new(AntiEntropyState::new(
            node_id.clone(),
            log.clone(),
        )));

        (
            Self {
                node_id,
                config,
                log,
                template_store,
                anti_entropy,
                peers: Arc::new(RwLock::new(HashMap::new())),
                peer_clocks: Arc::new(RwLock::new(HashMap::new())),
                template_tx,
                ext_log_tx,
                ext_template_tx,
            },
            template_rx,
        )
    }

    /// Create a gossip manager with persistent replication log.
    pub fn with_persistence(
        node_id: String,
        config: GossipConfig,
        ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
        ext_template_tx: broadcast::Sender<(u32, String)>,
        log_path: &str,
    ) -> anyhow::Result<(Self, TemplateRx)> {
        let (template_tx, template_rx) = mpsc::channel(100);
        let log = Arc::new(RwLock::new(ReplicationLog::with_persistence(
            node_id.clone(),
            log_path,
        )?));
        let template_store = Arc::new(RwLock::new(CRDTTemplateStore::new(node_id.clone())));
        let anti_entropy = Arc::new(RwLock::new(AntiEntropyState::new(
            node_id.clone(),
            log.clone(),
        )));

        Ok((
            Self {
                node_id,
                config,
                log,
                template_store,
                anti_entropy,
                peers: Arc::new(RwLock::new(HashMap::new())),
                peer_clocks: Arc::new(RwLock::new(HashMap::new())),
                ext_log_tx,
                template_tx,
                ext_template_tx,
            },
            template_rx,
        ))
    }

    /// Get the template sender.
    pub fn template_sender(&self) -> mpsc::Sender<(String, tokio::sync::oneshot::Sender<u32>)> {
        self.template_tx.clone()
    }

    /// Get peers reference.
    pub fn get_peers(&self) -> Arc<RwLock<HashMap<SocketAddr, PeerInfo>>> {
        self.peers.clone()
    }

    /// Get log reference.
    pub fn get_log(&self) -> Arc<RwLock<ReplicationLog>> {
        self.log.clone()
    }

    /// Get template store reference.
    pub fn get_template_store(&self) -> Arc<RwLock<CRDTTemplateStore>> {
        self.template_store.clone()
    }

    /// Add a new template locally and prepare for replication.
    pub async fn add_template(&self, pattern: String) -> (u32, LogEntry) {
        let template_id = {
            let mut store = self.template_store.write().await;
            store.add_template(pattern.clone())
        };

        // Create log entry
        let entry = {
            let mut log = self.log.write().await;
            log.append(ReplicationOp::NewTemplate {
                pattern: pattern.clone(),
                template_id,
            })
        };
        // Return entries to be gossiped
        // (In this simplified design, we let the polling loop handle it or expect this method to trigger it via side effect if we had the socket)
        // But main loop listens to template_rx which calls this.

        // Update anti-entropy state
        {
            let mut ae = self.anti_entropy.write().await;
            ae.add_template(&pattern, template_id);
        }

        // Notify external listeners
        // info!("Added local template: {} -> {}", template_id, pattern);
        let _ = self.ext_template_tx.send((template_id, pattern));

        // Also gossip this new template immediately?
        // Note: The caller (lib.rs template propagation task) receives the ID but doesn't have the log entry to gossip.
        // So we rely on the caller to not do anything, but who gossips it?
        // Ah, nobody gossips it immediately! The lib.rs just calls this and returns ID.
        // It relies on Anti-Entropy or Polling?
        // WE SHOULD GOSSIP IT HERE if we had the socket, but we don't.
        // Alternatively, since we can't gossip here, we should ensure the Pull mechanism picks it up or we redesign to allow gossiping from here.

        (template_id, entry)
    }

    pub async fn add_logs(&self, template_id: u32, variables: Vec<String>) -> LogEntry {
        let mut log = self.log.write().await;
        log.append(ReplicationOp::TemplateVariables {
            template_id,
            variables,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        })
    }

    /// Handle incoming replication message.
    pub async fn handle_message(
        &self,
        msg: ReplicationMessage,
        from_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> anyhow::Result<()> {
        match msg {
            ReplicationMessage::Heartbeat {
                node_id,
                vector_clock,
                template_count,
                log_length,
            } => {
                debug!(
                    "Heartbeat from {} (templates: {}, log: {})",
                    node_id, template_count, log_length
                );

                // Update peer info
                {
                    let mut peers = self.peers.write().await;
                    peers.insert(
                        from_addr,
                        PeerInfo {
                            node_id: node_id.clone(),
                            last_seen: chrono::Utc::now().timestamp(),
                            templates_count: template_count,
                        },
                    );
                }

                // Update peer clock
                {
                    let mut clocks = self.peer_clocks.write().await;
                    clocks.insert(node_id.clone(), vector_clock.clone());
                }

                // Check if we need to pull from this peer
                let our_clock = {
                    let log = self.log.read().await;
                    log.current_clock().clone()
                };

                if vector_clock.sum() > our_clock.sum() {
                    // They might have entries we don't have
                    let pull_req = ReplicationMessage::PullRequest {
                        from_node: self.node_id.clone(),
                        vector_clock: our_clock,
                    };
                    self.send_message(socket, from_addr, &pull_req).await?;
                }
            }

            ReplicationMessage::NewTemplate { entry } => {
                debug!("Received new template from {}", entry.origin_node);

                // Apply to log
                let applied = {
                    let mut log = self.log.write().await;
                    log.replicate(vec![entry.clone()])
                };

                if applied > 0 {
                    // Apply to template store
                    if let ReplicationOp::NewTemplate {
                        ref pattern,
                        template_id,
                    } = entry.operation
                    {
                        let mut store = self.template_store.write().await;
                        store.import_template(pattern.clone(), template_id, &entry.origin_node);

                        let mut ae = self.anti_entropy.write().await;
                        ae.add_template(pattern, template_id);

                        // Notify local listeners
                        let _ = self.ext_template_tx.send((template_id, pattern.clone()));
                    }

                    if let ReplicationOp::TemplateVariables {
                        template_id,
                        variables,
                        timestamp_ms,
                    } = &entry.operation
                    {
                        // info!("Gossip passing remote log to node: tid={}", template_id);
                        let _ =
                            self.ext_log_tx
                                .send((*template_id, variables.clone(), *timestamp_ms));
                    }

                    // Gossip to other peers
                    self.gossip_entry(entry, socket, Some(from_addr)).await?;
                }
            }

            ReplicationMessage::PullRequest {
                from_node,
                vector_clock,
            } => {
                debug!("Pull request from {}", from_node);

                let entries = {
                    let log = self.log.read().await;
                    let mut entries = log.entries_after_clock(&vector_clock);
                    entries.truncate(self.config.max_entries_per_pull);
                    entries
                };

                if !entries.is_empty() {
                    let response = ReplicationMessage::PullResponse { entries };
                    self.send_message(socket, from_addr, &response).await?;
                }
            }

            ReplicationMessage::PullResponse { entries } => {
                debug!("Received {} entries from pull", entries.len());

                for entry in entries {
                    let applied = {
                        let mut log = self.log.write().await;
                        log.replicate(vec![entry.clone()])
                    };

                    if applied > 0 {
                        match &entry.operation {
                            ReplicationOp::NewTemplate {
                                pattern,
                                template_id,
                            } => {
                                let mut store = self.template_store.write().await;
                                store.import_template(
                                    pattern.clone(),
                                    *template_id,
                                    &entry.origin_node,
                                );

                                let mut ae = self.anti_entropy.write().await;
                                ae.add_template(pattern, *template_id);

                                let _ = self.ext_template_tx.send((*template_id, pattern.clone()));
                            }
                            ReplicationOp::TemplateVariables {
                                template_id,
                                variables,
                                timestamp_ms,
                            } => {
                                let _ = self.ext_log_tx.send((
                                    *template_id,
                                    variables.clone(),
                                    *timestamp_ms,
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }

            ReplicationMessage::FullSyncRequest { from_node } => {
                info!("Full sync request from {}", from_node);

                let log_entries = {
                    let log = self.log.read().await;
                    log.all_entries().to_vec()
                };

                let crdt_state = {
                    let store = self.template_store.read().await;
                    postcard::to_allocvec(&store.export_state()).unwrap_or_default()
                };

                let response = ReplicationMessage::FullSyncResponse {
                    from_node: self.node_id.clone(),
                    log_entries,
                    crdt_state,
                };
                self.send_message(socket, from_addr, &response).await?;
            }

            ReplicationMessage::FullSyncResponse {
                from_node,
                log_entries,
                crdt_state,
            } => {
                info!(
                    "Full sync response from {} ({} entries)",
                    from_node,
                    log_entries.len()
                );

                // Merge log entries
                {
                    let mut log = self.log.write().await;
                    log.replicate(log_entries);
                }

                // Merge CRDT state
                if let Ok(other_store) = postcard::from_bytes::<CRDTTemplateStore>(&crdt_state) {
                    let mut store = self.template_store.write().await;
                    store.merge(&other_store);

                    // Update anti-entropy state
                    let mut ae = self.anti_entropy.write().await;
                    for template in other_store.all_templates() {
                        ae.add_template(&template.pattern, template.template_id);
                        let _ = self
                            .ext_template_tx
                            .send((template.template_id, template.pattern.clone()));
                    }
                }
            }

            ReplicationMessage::AntiEntropy(ae_msg) => {
                let mut ae = self.anti_entropy.write().await;

                match ae_msg {
                    AntiEntropyMessage::SyncRequest { .. } => {
                        if let Some(response) = ae.handle_sync_request(ae_msg).await {
                            let wrapper = ReplicationMessage::AntiEntropy(response);
                            self.send_message(socket, from_addr, &wrapper).await?;
                        }
                    }
                    AntiEntropyMessage::SyncResponse { .. } => {
                        ae.handle_sync_response(ae_msg).await;
                    }
                    _ => {}
                }
            }

            ReplicationMessage::Ack {
                from_node,
                last_seq,
            } => {
                debug!("Ack from {} for seq {}", from_node, last_seq);
            }
        }

        Ok(())
    }

    /// Gossip an entry to peers.
    pub async fn gossip_entry(
        &self,
        entry: LogEntry,
        socket: &UdpSocket,
        exclude: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        let peers = self.peers.read().await;
        let msg = ReplicationMessage::NewTemplate { entry };

        let mut sent = 0;
        for (addr, _) in peers.iter() {
            if Some(*addr) == exclude {
                continue;
            }
            if sent >= self.config.gossip_fanout {
                break;
            }

            self.send_message(socket, *addr, &msg).await?;
            sent += 1;
        }

        Ok(())
    }

    /// Send a replication message.
    async fn send_message(
        &self,
        socket: &UdpSocket,
        to: SocketAddr,
        msg: &ReplicationMessage,
    ) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(msg)?;
        socket.send_to(&bytes, to).await?;
        Ok(())
    }

    /// Generate heartbeat message.
    pub async fn generate_heartbeat(&self) -> ReplicationMessage {
        let (vector_clock, log_length) = {
            let log = self.log.read().await;
            (log.current_clock().clone(), log.len())
        };

        let template_count = {
            let store = self.template_store.read().await;
            store.len() as u32
        };

        ReplicationMessage::Heartbeat {
            node_id: self.node_id.clone(),
            vector_clock,
            template_count,
            log_length,
        }
    }

    /// Generate anti-entropy sync request.
    pub async fn generate_sync_request(&self) -> ReplicationMessage {
        let ae = self.anti_entropy.read().await;
        let request = ae.generate_sync_request().await;
        ReplicationMessage::AntiEntropy(request)
    }

    /// Cleanup stale peers.
    pub async fn cleanup_peers(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut peers = self.peers.write().await;
        peers.retain(|_, info| now - info.last_seen < self.config.peer_timeout_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gossip_manager_creation() {
        let (tx, _rx) = broadcast::channel(100);
        let (log_tx, _log_rx) = broadcast::channel(100);
        let config = GossipConfig::default();
        let (manager, _template_rx) = GossipManager::new("node1".to_string(), config, tx, log_tx);

        let heartbeat = manager.generate_heartbeat().await;
        match heartbeat {
            ReplicationMessage::Heartbeat {
                node_id,
                template_count,
                ..
            } => {
                assert_eq!(node_id, "node1");
                assert_eq!(template_count, 0);
            }
            _ => panic!("Expected heartbeat"),
        }
    }

    #[tokio::test]
    async fn test_add_template() {
        let (tx, _rx) = broadcast::channel(100);
        let (log_tx, _log_rx) = broadcast::channel(100);
        let config = GossipConfig::default();
        let (manager, _template_rx) = GossipManager::new("node1".to_string(), config, tx, log_tx);

        let _id = manager.add_template("Test <*>".to_string()).await;

        let store = manager.get_template_store();
        let store_lock = store.read().await;
        assert_eq!(store_lock.len(), 1);
        assert!(store_lock.get_template("Test <*>").is_some());
    }
}
