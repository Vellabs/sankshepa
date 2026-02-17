//! AP Cluster Module for Sankshepa
//!
//! This module implements a highly available distributed cluster with
//! Availability and Partition tolerance (AP) guarantees using:
//!
//! - **Replication Log**: Append-only operation log for durability and sync
//! - **Vector Clocks**: Causality tracking for conflict detection
//! - **Merkle Trees**: Efficient anti-entropy synchronization
//! - **CRDTs**: Conflict-free replicated data types for eventual consistency
//! - **Gossip Protocol**: Epidemic dissemination of templates and variables

pub mod anti_entropy;
pub mod crdt;
pub mod gossip;
pub mod merkle_tree;
pub mod replication_log;
pub mod vector_clock;

use chrono::Utc;
use gossip::{GossipConfig, GossipManager, ReplicationMessage};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast, mpsc};
use tracing::{debug, info, warn};

/// Information about a peer node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: String,
    pub last_seen: i64,
    pub templates_count: u32,
}

/// Legacy cluster message types (kept for compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterMessage {
    Heartbeat {
        node_id: String,
        templates_count: u32,
    },
    NewTemplate {
        pattern: String,
    },
    SyncState(Vec<String>),
}

/// Cluster manager with AP guarantees.
///
/// This manager implements:
/// - Heartbeat-based failure detection
/// - Gossip-based template propagation
/// - Anti-entropy synchronization for consistency repair
/// - CRDT-based template storage for conflict-free merging
pub struct ClusterManager {
    node_id: String,
    bind_addr: SocketAddr,
    known_peers: Vec<String>,
    gossip_manager: GossipManager,
    #[allow(dead_code)]
    template_rx: mpsc::Receiver<(String, tokio::sync::oneshot::Sender<u32>)>,
    /// Log variables sender
    log_sender: mpsc::Sender<(u32, Vec<String>)>,
    log_receiver: Option<mpsc::Receiver<(u32, Vec<String>)>>,
}

impl ClusterManager {
    /// Create a new cluster manager with default configuration.
    pub fn new(
        node_id: String,
        bind_addr: SocketAddr,
        initial_peers: Vec<String>,
        ext_template_tx: broadcast::Sender<(u32, String)>,
        ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
    ) -> Self {
        Self::with_config(
            node_id,
            bind_addr,
            initial_peers,
            ext_template_tx,
            ext_log_tx,
            GossipConfig::default(),
            None,
        )
    }

    /// Create a cluster manager with persistent replication log.
    pub fn with_persistence(
        node_id: String,
        bind_addr: SocketAddr,
        initial_peers: Vec<String>,
        ext_template_tx: broadcast::Sender<(u32, String)>,
        ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
        log_path: String,
    ) -> anyhow::Result<Self> {
        let (gossip_manager, template_rx) = GossipManager::with_persistence(
            node_id.clone(),
            GossipConfig::default(),
            ext_log_tx.clone(),
            ext_template_tx.clone(),
            &log_path,
        )?;

        let (log_sender, log_receiver) = mpsc::channel(100);

        Ok(Self {
            node_id,
            bind_addr,
            known_peers: initial_peers,
            gossip_manager,
            template_rx,
            log_sender,
            log_receiver: Some(log_receiver),
        })
    }

    /// Create a cluster manager with custom configuration.
    pub fn with_config(
        node_id: String,
        bind_addr: SocketAddr,
        initial_peers: Vec<String>,
        ext_template_tx: broadcast::Sender<(u32, String)>,
        ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
        config: GossipConfig,
        log_path: Option<String>,
    ) -> Self {
        let (gossip_manager, template_rx) = if let Some(path) = log_path {
            match GossipManager::with_persistence(
                node_id.clone(),
                config.clone(),
                ext_log_tx.clone(),
                ext_template_tx.clone(),
                &path,
            ) {
                Ok(gm) => gm,
                Err(e) => {
                    warn!("Failed to enable persistence at {}: {}. Falling back to non-persistent mode.", path, e);
                    GossipManager::new(
                        node_id.clone(),
                        config,
                        ext_template_tx.clone(),
                        ext_log_tx.clone(),
                    )
                }
            }
        } else {
            GossipManager::new(
                node_id.clone(),
                config,
                ext_template_tx.clone(),
                ext_log_tx.clone(),
            )
        };

        let (log_sender, log_receiver) = mpsc::channel(100);

        Self {
            node_id,
            bind_addr,
            known_peers: initial_peers,
            gossip_manager,
            template_rx,
            log_sender,
            log_receiver: Some(log_receiver),
        }
    }

    pub async fn ensure_template(&self, pattern: String) -> Option<u32> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sender = self.gossip_manager.template_sender();

        if sender.send((pattern, tx)).await.is_ok() {
            rx.await.ok()
        } else {
            None
        }
    }

    pub fn log_sender(&self) -> mpsc::Sender<(u32, Vec<String>)> {
        self.log_sender.clone()
    }

    /// Get the template sender for adding new templates.
    pub fn get_template_sender(&self) -> mpsc::Sender<(String, tokio::sync::oneshot::Sender<u32>)> {
        self.gossip_manager.template_sender()
    }

    /// Alias for compatibility - use get_template_sender instead.
    #[deprecated(note = "Use get_template_sender() instead")]
    pub fn template_tx_clone(&self) -> mpsc::Sender<(String, tokio::sync::oneshot::Sender<u32>)> {
        self.gossip_manager.template_sender()
    }

    /// Get the template sender (legacy compatibility).
    pub fn template_tx(&self) -> mpsc::Sender<(String, tokio::sync::oneshot::Sender<u32>)> {
        self.gossip_manager.template_sender()
    }

    /// Get peers reference.
    pub fn get_peers(&self) -> Arc<RwLock<HashMap<SocketAddr, PeerInfo>>> {
        self.gossip_manager.get_peers()
    }

    /// Get the replication log reference.
    pub fn get_log(&self) -> Arc<RwLock<replication_log::ReplicationLog>> {
        self.gossip_manager.get_log()
    }

    /// Get the CRDT template store reference.
    pub fn get_template_store(&self) -> Arc<RwLock<crdt::CRDTTemplateStore>> {
        self.gossip_manager.get_template_store()
    }

    /// Run the cluster manager.
    pub async fn run(self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        info!(
            "AP Cluster manager started on {} (Node ID: {})",
            self.bind_addr, self.node_id
        );
        info!("Features: Replication Log, Vector Clocks, Merkle Trees, CRDTs, Gossip");

        let socket = Arc::new(socket);
        let initial_peers = self.known_peers.clone();
        let _node_id = self.node_id.clone();

        // Heartbeat sender task
        let socket_hb = socket.clone();
        let gossip_hb = Arc::new(self.gossip_manager);
        let gossip_for_hb = gossip_hb.clone();
        let initial_peers_hb = initial_peers.clone();
        tokio::spawn(async move {
            loop {
                let heartbeat = gossip_for_hb.generate_heartbeat().await;
                if let Ok(bytes) = serde_json::to_vec(&heartbeat) {
                    for peer in &initial_peers_hb {
                        if let Ok(addrs) = tokio::net::lookup_host(peer).await {
                            for addr in addrs {
                                let _ = socket_hb.send_to(&bytes, addr).await;
                            }
                        }
                    }
                    // Also send to known peers
                    let peers = gossip_for_hb.get_peers();
                    let peers_lock = peers.read().await;
                    for addr in peers_lock.keys() {
                        let _ = socket_hb.send_to(&bytes, *addr).await;
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });

        // Anti-entropy sync task
        let socket_ae = socket.clone();
        let gossip_for_ae = gossip_hb.clone();
        let initial_peers_ae = initial_peers.clone();
        tokio::spawn(async move {
            // Initial delay to let peers discover each other
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            loop {
                let sync_request = gossip_for_ae.generate_sync_request().await;
                if let Ok(bytes) = serde_json::to_vec(&sync_request) {
                    // Send to a random subset of peers
                    let peers = gossip_for_ae.get_peers();
                    let peers_lock = peers.read().await;
                    for addr in peers_lock.keys().take(3) {
                        debug!("Sending anti-entropy sync to {}", addr);
                        let _ = socket_ae.send_to(&bytes, *addr).await;
                    }
                    // Also try initial peers
                    for peer in initial_peers_ae.iter().take(2) {
                        if let Ok(addrs) = tokio::net::lookup_host(peer).await {
                            for addr in addrs {
                                let _ = socket_ae.send_to(&bytes, addr).await;
                            }
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        });

        // Peer cleanup task
        let gossip_for_cleanup = gossip_hb.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                gossip_for_cleanup.cleanup_peers().await;
            }
        });

        // Template propagation task (receives from local template_tx)
        let socket_prop = socket.clone();
        let gossip_for_prop = gossip_hb.clone();
        let mut template_rx = self.template_rx;
        tokio::spawn(async move {
            while let Some((pattern, reply_tx)) = template_rx.recv().await {
                let (id, entry) = gossip_for_prop.add_template(pattern.clone()).await;
                if let Err(e) = reply_tx.send(id) {
                    warn!("Failed to reply with template ID: {}", e);
                }

                // Gossip immediately
                if let Err(e) = gossip_for_prop
                    .gossip_entry(entry, &socket_prop, None)
                    .await
                {
                    warn!("Failed to gossip new template: {}", e);
                }
            }
        });

        // Log Propagation task
        let gossip_for_logs = gossip_hb.clone();
        let socket_logs = socket.clone();
        let mut log_rx = self.log_receiver.unwrap();
        tokio::spawn(async move {
            while let Some((tid, vars)) = log_rx.recv().await {
                let entry = gossip_for_logs.add_logs(tid, vars).await;
                if let Err(e) = gossip_for_logs
                    .gossip_entry(entry, &socket_logs, None)
                    .await
                {
                    tracing::warn!("Failed to gossip log entry: {}", e);
                }
            }
        });

        // Main receiver loop
        let mut buf = [0u8; 65535];
        loop {
            let (len, addr) = socket.recv_from(&mut buf).await?;

            // Try to parse as new ReplicationMessage first
            if let Ok(msg) = serde_json::from_slice::<ReplicationMessage>(&buf[..len]) {
                if let Err(e) = gossip_hb.handle_message(msg, addr, &socket).await {
                    warn!("Error handling replication message from {}: {}", addr, e);
                }
                continue;
            }

            // Fall back to legacy ClusterMessage for compatibility
            if let Ok(msg) = serde_json::from_slice::<ClusterMessage>(&buf[..len]) {
                match msg {
                    ClusterMessage::Heartbeat {
                        node_id: peer_id,
                        templates_count,
                    } => {
                        debug!("Legacy heartbeat from {} ({})", peer_id, addr);
                        let peers = gossip_hb.get_peers();
                        let mut peers_lock = peers.write().await;
                        peers_lock.insert(
                            addr,
                            PeerInfo {
                                node_id: peer_id,
                                last_seen: Utc::now().timestamp(),
                                templates_count,
                            },
                        );
                    }
                    ClusterMessage::NewTemplate { pattern } => {
                        debug!("Legacy new template from {}: {}", addr, pattern);
                        // Import into the new system
                        gossip_hb.add_template(pattern).await;
                    }
                    ClusterMessage::SyncState(patterns) => {
                        debug!("Legacy sync state with {} patterns", patterns.len());
                        for pattern in patterns {
                            gossip_hb.add_template(pattern).await;
                        }
                    }
                }
            }
        }
    }
}

/// Builder for ClusterManager with fluent API.
pub struct ClusterManagerBuilder {
    node_id: String,
    bind_addr: SocketAddr,
    initial_peers: Vec<String>,
    ext_template_tx: broadcast::Sender<(u32, String)>,
    ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
    config: GossipConfig,
    log_path: Option<String>,
}

impl ClusterManagerBuilder {
    /// Create a new builder.
    pub fn new(
        node_id: String,
        bind_addr: SocketAddr,
        ext_template_tx: broadcast::Sender<(u32, String)>,
        ext_log_tx: broadcast::Sender<(u32, Vec<String>, i64)>,
    ) -> Self {
        Self {
            node_id,
            bind_addr,
            initial_peers: Vec::new(),
            ext_template_tx,
            ext_log_tx,
            config: GossipConfig::default(),
            log_path: None,
        }
    }

    /// Add initial peers.
    pub fn with_peers(mut self, peers: Vec<String>) -> Self {
        self.initial_peers = peers;
        self
    }

    /// Set heartbeat interval.
    pub fn with_heartbeat_interval(mut self, secs: u64) -> Self {
        self.config.heartbeat_interval_secs = secs;
        self
    }

    /// Set sync interval.
    pub fn with_sync_interval(mut self, secs: u64) -> Self {
        self.config.sync_interval_secs = secs;
        self
    }

    /// Set gossip fanout.
    pub fn with_fanout(mut self, fanout: usize) -> Self {
        self.config.gossip_fanout = fanout;
        self
    }

    /// Set log persistence path.
    pub fn with_persistence(mut self, path: String) -> Self {
        self.log_path = Some(path);
        self
    }

    /// Build the ClusterManager.
    pub fn build(self) -> ClusterManager {
        ClusterManager::with_config(
            self.node_id,
            self.bind_addr,
            self.initial_peers,
            self.ext_template_tx,
            self.ext_log_tx,
            self.config,
            self.log_path,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let (tx, _rx) = broadcast::channel(100);
        let (log_tx, _log_rx) = broadcast::channel(100);
        let addr: SocketAddr = "127.0.0.1:1701".parse().unwrap();

        let manager = ClusterManagerBuilder::new("node1".to_string(), addr, tx, log_tx)
            .with_peers(vec!["127.0.0.1:1702".to_string()])
            .with_heartbeat_interval(10)
            .with_sync_interval(60)
            .with_fanout(5)
            .build();

        assert_eq!(manager.node_id, "node1");
    }
}
