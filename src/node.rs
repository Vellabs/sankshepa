use anyhow::Context;
use sankshepa_cluster::ClusterManager;
use sankshepa_ingestion::IngestionServer;
use sankshepa_protocol::SyslogMessage;
use sankshepa_storage::StorageManager;
use sankshepa_storage::logshrink::LogChunk;
use sankshepa_ui::{UiMessage, UiServer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

pub struct NodeConfig {
    pub udp_addr: String,
    pub tcp_addr: String,
    pub beep_addr: String,
    pub ui_addr: String,
    pub output_path: String,
    pub node_id: String,
    pub cluster_addr: String,
    pub peers: Vec<String>,
}

pub struct Node {
    config: NodeConfig,
    storage_manager: Arc<StorageManager>,
    template_map: Arc<RwLock<HashMap<u32, String>>>,
    ui_tx: broadcast::Sender<UiMessage>,
}

impl Node {
    pub fn new(config: NodeConfig) -> anyhow::Result<Self> {
        // 1GB max size, 24 hours retention
        let storage_manager = Arc::new(StorageManager::new(
            &config.output_path,
            1024 * 1024 * 1024,
            24,
        ));

        let (ui_tx, _) = broadcast::channel(1000);
        let template_map = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            config,
            storage_manager,
            template_map,
            ui_tx,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let (ingestion_tx, mut ingestion_rx) = mpsc::channel(100);
        let (cluster_template_tx, mut cluster_template_rx) = broadcast::channel(100);
        let (cluster_log_tx, mut cluster_log_rx) = broadcast::channel(100);

        let ingestion_server = IngestionServer::new(
            self.config.udp_addr.clone(),
            self.config.tcp_addr.clone(),
            self.config.beep_addr.clone(),
            ingestion_tx,
        );

        let ui_server = UiServer::new(self.ui_tx.clone());

        let cluster_socket_addr: SocketAddr = self
            .config
            .cluster_addr
            .parse()
            .context("Invalid cluster address")?;

        let cluster_manager = ClusterManager::new(
            self.config.node_id.clone(),
            cluster_socket_addr,
            self.config.peers.clone(),
            cluster_template_tx.clone(),
            cluster_log_tx.clone(),
        );

        let cluster_tx = cluster_manager.get_template_sender(); // Use new method
        let cluster_log_sender = cluster_manager.log_sender();

        let log_count = Arc::new(AtomicUsize::new(0));
        let variable_count = Arc::new(AtomicUsize::new(0));
        let total_original_size = Arc::new(AtomicU64::new(0));
        let total_compressed_size = Arc::new(AtomicU64::new(0));

        // Stats update task
        let ui_tx_stats = self.ui_tx.clone();
        let template_map_stats = self.template_map.clone();
        let log_count_stats = log_count.clone();
        let variable_count_stats = variable_count.clone();
        let orig_size_stats = total_original_size.clone();
        let comp_size_stats = total_compressed_size.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                let template_count = template_map_stats.read().unwrap().len() as u32;
                let log_cnt = log_count_stats.load(Ordering::Relaxed);
                let var_cnt = variable_count_stats.load(Ordering::Relaxed);
                let orig_size = orig_size_stats.load(Ordering::Relaxed);
                let comp_size = comp_size_stats.load(Ordering::Relaxed);

                let _ = ui_tx_stats.send(UiMessage::Stats {
                    template_count,
                    log_count: log_cnt,
                    variable_count: var_cnt,
                    original_size: orig_size,
                    compressed_size: comp_size,
                });
            }
        });

        // Background task: Process cluster events (templates and logs) with coordination
        let template_map_clone = self.template_map.clone();
        let ui_tx_clone = self.ui_tx.clone();
        let log_count_cluster = log_count.clone();
        let variable_count_cluster = variable_count.clone();
        let pending_logs_path = PathBuf::from(&self.config.output_path).with_extension("pending");

        tokio::spawn(async move {
            let mut pending_logs: HashMap<u32, Vec<(Vec<String>, i64)>> =
                if pending_logs_path.exists() {
                    match tokio::fs::read(&pending_logs_path)
                        .await
                        .and_then(|b| postcard::from_bytes(&b).map_err(std::io::Error::other))
                    {
                        Ok(logs) => logs,
                        Err(e) => {
                            warn!("Failed to load pending logs: {}. Starting fresh.", e);
                            HashMap::new()
                        }
                    }
                } else {
                    HashMap::new()
                };

            loop {
                tokio::select! {
                    res = cluster_template_rx.recv() => {
                        match res {
                            Ok((tid, pattern)) => {
                                info!("Received cluster template: {} -> {}", tid, pattern);
                                {
                                    let mut map = template_map_clone.write().unwrap();
                                    map.insert(tid, pattern.clone());
                                }

                                // Process any pending logs for this template
                                if let Some(logs) = pending_logs.remove(&tid) {
                                    info!("Processing {} pending logs for template {}", logs.len(), tid);
                                    for (vars, ts) in logs {
                                        let mut msg_str = pattern.clone();
                                        for var in &vars {
                                            msg_str = msg_str.replacen("<*>", var, 1);
                                        }

                                        let msg = SyslogMessage {
                                            priority: 13,
                                            facility: 1,
                                            severity: 5,
                                            timestamp: Some(
                                                chrono::DateTime::from_timestamp_millis(ts)
                                                    .unwrap_or_else(chrono::Utc::now),
                                            ),
                                            hostname: Some("cluster-peer".to_string()),
                                            app_name: Some("replicated".to_string()),
                                            procid: None,
                                            msgid: None,
                                            structured_data: None,
                                            message: msg_str,
                                            is_rfc5424: false,
                                            node_id: Some("cluster".to_string()),
                                        };
                                        let _ = ui_tx_clone.send(UiMessage::Log(msg));
                                    }
                                    // Save updated pending logs
                                    if let Ok(bytes) = postcard::to_allocvec(&pending_logs) {
                                        let _ = tokio::fs::write(&pending_logs_path, bytes).await;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("Cluster template receiver lagged by {}", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                tracing::error!("Cluster template receiver closed");
                                break;
                            }
                        }
                    }
                    res = cluster_log_rx.recv() => {
                        match res {
                            Ok((tid, vars, ts)) => {
                                log_count_cluster.fetch_add(1, Ordering::Relaxed);
                                variable_count_cluster.fetch_add(vars.len(), Ordering::Relaxed);

                                let should_buffer = {
                                    let map = template_map_clone.read().unwrap();
                                    !map.contains_key(&tid)
                                };

                                if should_buffer {
                                    info!("Buffering log for unknown template {}. Map size: {}",
                                        tid, template_map_clone.read().unwrap().len());
                                    pending_logs.entry(tid).or_default().push((vars, ts));

                                    // Periodic persistence (or every log for maximum durability)
                                    if let Ok(bytes) = postcard::to_allocvec(&pending_logs) {
                                        let _ = tokio::fs::write(&pending_logs_path, bytes).await;
                                    }
                                } else if let Some(msg) =
                                    Self::reconstruct_cluster_log(tid, vars, ts, &template_map_clone)
                                {
                                    // info!("Reconstructed cluster log: {}", msg.message);
                                    let _ = ui_tx_clone.send(UiMessage::Log(msg));
                                } else {
                                    error!("Failed to reconstruct cluster log for tid={}", tid);
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("Cluster log receiver lagged by {}", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                tracing::error!("Cluster log receiver closed");
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Main orchestration loop
        let storage_manager = self.storage_manager.clone();
        let node_id = self.config.node_id.clone();
        let ui_tx = self.ui_tx.clone();
        let log_count_ingest = log_count.clone();
        let variable_count_ingest = variable_count.clone();

        let storage_handle = tokio::spawn(async move {
            let mut chunk = LogChunk::new();
            let mut count = 0;

            loop {
                tokio::select! {
                    Some(mut msg) = ingestion_rx.recv() => {
                        log_count_ingest.fetch_add(1, Ordering::Relaxed);
                        msg.node_id = Some(node_id.clone());
                        let _ = ui_tx.send(UiMessage::Log(msg.clone()));
                        chunk.add_message(msg);
                        count += 1;
                        if count >= 10 {
                            let vars = Self::flush_chunk(&mut chunk, &storage_manager, &cluster_tx, &cluster_log_sender, &total_original_size, &total_compressed_size).await;
                            variable_count_ingest.fetch_add(vars, Ordering::Relaxed);
                            count = 0;
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        if count > 0 {
                            let vars = Self::flush_chunk(&mut chunk, &storage_manager, &cluster_tx, &cluster_log_sender, &total_original_size, &total_compressed_size).await;
                            variable_count_ingest.fetch_add(vars, Ordering::Relaxed);
                        }
                        break;
                    }
                }
            }
        });

        let ui_addr = self.config.ui_addr.clone();
        let ui_handle = tokio::spawn(async move { ui_server.run(&ui_addr).await });
        let cluster_handle = tokio::spawn(async move { cluster_manager.run().await });

        info!("Sankshepa Node {} started", self.config.node_id);

        tokio::select! {
            res = ingestion_server.run() => {
                if let Err(e) = res { error!("Ingestion error: {}", e); }
            }
            res = ui_handle => {
                match res {
                    Ok(Ok(_)) => info!("UI server stopped"),
                    Ok(Err(e)) => error!("UI error: {}", e),
                    Err(e) => error!("UI task panicked: {}", e),
                }
            }
            res = cluster_handle => {
                match res {
                    Ok(Ok(_)) => info!("Cluster stopped"),
                    Ok(Err(e)) => error!("Cluster error: {}", e),
                    Err(e) => error!("Cluster task panicked: {}", e),
                }
            }
            _ = storage_handle => {
                info!("Storage handler stopped");
            }
        }

        Ok(())
    }

    async fn flush_chunk(
        chunk: &mut LogChunk,
        storage_manager: &StorageManager,
        cluster_tx: &mpsc::Sender<(String, tokio::sync::oneshot::Sender<u32>)>,
        cluster_log_sender: &mpsc::Sender<(u32, Vec<String>)>,
        stats_orig: &AtomicU64,
        stats_comp: &AtomicU64,
    ) -> usize {
        let original_size: usize = chunk.raw_messages.iter().map(|m| m.message.len()).sum();
        chunk.finish_and_process();

        stats_orig.fetch_add(original_size as u64, Ordering::Relaxed);

        let mut local_to_global = HashMap::new();
        let mut variable_count = 0;

        // Resolve all local templates to Global IDs
        for (pattern, &local_id) in &chunk.templates {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Err(e) = cluster_tx.send((pattern.clone(), tx)).await {
                warn!(
                    "Failed to send template '{}' for global ID resolution: {}",
                    pattern, e
                );
                continue;
            }

            match rx.await {
                Ok(global_id) => {
                    local_to_global.insert(local_id, global_id);
                }
                Err(e) => {
                    warn!(
                        "Failed to receive global ID for template '{}': {}",
                        pattern, e
                    );
                }
            }
        }

        for record in &chunk.records {
            variable_count += record.variables.len();
            if let Some(&global_id) = local_to_global.get(&record.template_id)
                && let Err(e) = cluster_log_sender
                    .send((global_id, record.variables.clone()))
                    .await
            {
                warn!(
                    "Failed to send replicated log for global template ID {}: {}",
                    global_id, e
                );
            }
        }

        match storage_manager.write_chunk(std::mem::take(chunk)) {
            Ok(size) => {
                stats_comp.fetch_add(size, Ordering::Relaxed);
                info!("Saved chunk to storage ({} bytes)", size);
            }
            Err(e) => {
                error!("Failed to write chunk: {}", e);
            }
        }
        variable_count
    }

    fn reconstruct_cluster_log(
        tid: u32,
        vars: Vec<String>,
        ts: i64,
        template_map: &RwLock<HashMap<u32, String>>,
    ) -> Option<SyslogMessage> {
        let pattern = {
            let map = template_map.read().unwrap();
            map.get(&tid).cloned()?
        };

        let mut msg_str = pattern;
        for var in vars {
            msg_str = msg_str.replacen("<*>", &var, 1);
        }

        Some(SyslogMessage {
            priority: 13,
            facility: 1,
            severity: 5,
            timestamp: Some(
                chrono::DateTime::from_timestamp_millis(ts).unwrap_or_else(chrono::Utc::now),
            ),
            hostname: Some("cluster-peer".to_string()),
            app_name: Some("replicated".to_string()),
            procid: None,
            msgid: None,
            structured_data: None,
            message: msg_str,
            is_rfc5424: false,
            node_id: Some("cluster".to_string()),
        })
    }
}
