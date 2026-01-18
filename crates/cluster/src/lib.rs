use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast, mpsc};
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub last_seen: i64,
    pub templates_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterMessage {
    Heartbeat {
        node_id: String,
        templates_count: u32,
    },
    NewTemplate {
        pattern: String,
    },
    SyncState(Vec<String>), // List of patterns
}

pub struct ClusterManager {
    node_id: String,
    bind_addr: SocketAddr,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    known_peers: Vec<SocketAddr>,
    pub template_tx: mpsc::Sender<String>,
    template_rx: Arc<RwLock<mpsc::Receiver<String>>>,
    ext_template_tx: broadcast::Sender<String>,
}

impl ClusterManager {
    pub fn new(
        node_id: String,
        bind_addr: SocketAddr,
        initial_peers: Vec<SocketAddr>,
        ext_template_tx: broadcast::Sender<String>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            node_id,
            bind_addr,
            peers: Arc::new(RwLock::new(HashMap::new())),
            known_peers: initial_peers,
            template_tx: tx,
            template_rx: Arc::new(RwLock::new(rx)),
            ext_template_tx,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        info!(
            "Cluster manager started on {} (Node ID: {})",
            self.bind_addr, self.node_id
        );

        let socket = Arc::new(socket);
        let peers = self.peers.clone();
        let node_id = self.node_id.clone();
        let initial_peers = self.known_peers.clone();
        let template_rx = self.template_rx.clone();
        let ext_template_tx = self.ext_template_tx.clone();

        // Heartbeat sender task
        let socket_send = socket.clone();
        let node_id_send = node_id.clone();
        tokio::spawn(async move {
            loop {
                let msg = ClusterMessage::Heartbeat {
                    node_id: node_id_send.clone(),
                    templates_count: 0,
                };
                let bytes = serde_json::to_vec(&msg).unwrap();
                for peer in &initial_peers {
                    let _ = socket_send.send_to(&bytes, peer).await;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });

        // Template propagation task
        let socket_prop = socket.clone();
        let peers_prop = peers.clone();
        tokio::spawn(async move {
            let mut rx = template_rx.write().await;
            while let Some(pattern) = rx.recv().await {
                debug!("Propagating new template: {}", pattern);
                let msg = ClusterMessage::NewTemplate { pattern };
                if let Ok(bytes) = serde_json::to_vec(&msg) {
                    let peers_lock = peers_prop.read().await;
                    for addr in peers_lock.keys() {
                        let _ = socket_prop.send_to(&bytes, addr).await;
                    }
                }
            }
        });

        // Receiver loop
        let mut buf = [0u8; 65535];
        loop {
            let (len, addr) = socket.recv_from(&mut buf).await?;
            let msg: Result<ClusterMessage, _> = serde_json::from_slice(&buf[..len]);

            match msg {
                Ok(ClusterMessage::Heartbeat {
                    node_id: peer_id,
                    templates_count,
                }) => {
                    debug!("Received heartbeat from {} ({})", peer_id, addr);
                    let mut peers_lock = peers.write().await;
                    peers_lock.insert(
                        addr,
                        PeerInfo {
                            last_seen: Utc::now().timestamp(),
                            templates_count,
                        },
                    );
                }
                Ok(ClusterMessage::NewTemplate { pattern }) => {
                    debug!("Received new template from {}: {}", addr, pattern);
                    let _ = ext_template_tx.send(pattern);
                }
                _ => {}
            }
        }
    }
}
