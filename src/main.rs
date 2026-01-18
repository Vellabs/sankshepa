use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use sankshepa_ingestion::IngestionServer;
use sankshepa_protocol::UnifiedParser;
use sankshepa_storage::StorageEngine;
use sankshepa_storage::logshrink::LogChunk;
use sankshepa_ui::UiServer;
use std::io::{self, Write};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "sankshepa")]
#[command(about = "Multi-Protocol Syslog Suite with LogShrink Storage", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Starts the syslog collector
    Serve {
        #[arg(long, default_value = "127.0.0.1:1514")]
        udp_addr: String,
        #[arg(long, default_value = "127.0.0.1:1514")]
        tcp_addr: String,
        #[arg(long, default_value = "127.0.0.1:1601")]
        beep_addr: String,
        #[arg(long, default_value = "127.0.0.1:8080")]
        ui_addr: String,
        #[arg(long, default_value = "logs.lshrink")]
        output: String,
    },
    /// Extracts and reconstructs logs from LogShrink storage
    Query {
        #[arg(long, default_value = "logs.lshrink")]
        input: String,
        #[arg(long)]
        template_id: Option<u32>,
        /// Search string to filter logs
        #[arg(long)]
        filter: Option<String>,
    },
    /// Generates test syslog messages
    Generate {
        #[arg(long, default_value = "127.0.0.1:1514")]
        addr: String,
        #[arg(long, default_value = "tcp")]
        protocol: String,
        #[arg(long, default_value = "20")]
        count: usize,
    },
    /// Benchmarks storage gains by comparing raw logs vs LogShrink storage
    Bench {
        #[arg(long, default_value = "10000")]
        count: usize,
        #[arg(long, default_value = "bench.lshrink")]
        output: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        unsafe { std::env::set_var("RUST_LOG", "info,sankshepa=debug") };
    }
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            udp_addr,
            tcp_addr,
            beep_addr,
            ui_addr,
            output,
        } => {
            let (tx, mut rx) = mpsc::channel(100);
            let (ui_tx, _) = broadcast::channel(1000);

            let server = IngestionServer::new(udp_addr, tcp_addr, beep_addr, tx);
            let ui_server = UiServer::new(ui_tx.clone());

            let output_path = output.clone();
            let ui_tx_clone = ui_tx.clone();
            let storage_handle = tokio::spawn(async move {
                let mut chunk = LogChunk::new();
                let mut count = 0;
                loop {
                    tokio::select! {
                        Some(msg) = rx.recv() => {
                            let _ = ui_tx_clone.send(msg.clone());
                            chunk.add_message(msg);
                            count += 1;
                            if count >= 10 {
                                chunk.finish_and_process();
                                let _ = StorageEngine::save_chunk(chunk, &output_path);
                                chunk = LogChunk::new();
                                count = 0;
                                info!("Saved chunk to {}", output_path);
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            if count > 0 {
                                chunk.finish_and_process();
                                let _ = StorageEngine::save_chunk(chunk, &output_path);
                                info!("Saved final chunk on Ctrl-C");
                            }
                            break;
                        }
                    }
                }
            });

            let ui_handle = tokio::spawn(async move { ui_server.run(&ui_addr).await });

            tokio::select! {
                res = server.run() => {
                    if let Err(e) = res {
                        error!("Ingestion server error: {}", e);
                    }
                }
                res = ui_handle => {
                    match res {
                        Ok(Ok(_)) => info!("UI server stopped"),
                        Ok(Err(e)) => error!("UI server error: {}", e),
                        Err(e) => error!("UI task panicked: {}", e),
                    }
                }
                _ = storage_handle => {
                    info!("Storage handler stopped");
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal received");
                }
            }
            info!("Sankshepa shutting down...");
        }
        Commands::Query {
            input,
            template_id,
            filter,
        } => {
            let chunk = StorageEngine::load_chunk(&input)?;

            let mut pattern_map = std::collections::HashMap::new();
            for (pattern, &id) in &chunk.templates {
                pattern_map.insert(id, pattern.clone());
            }

            let filter_lower = filter.as_ref().map(|s| s.to_lowercase());
            let mut stdout = io::stdout().lock();

            for record in chunk.records {
                if template_id.is_some_and(|tid| record.template_id != tid) {
                    continue;
                }

                let pattern = pattern_map
                    .get(&record.template_id)
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".to_string());
                let mut reconstructed = pattern.clone();
                for var in record.variables {
                    reconstructed = reconstructed.replacen("<*>", &var, 1);
                }

                let host = record
                    .hostname_id
                    .and_then(|id| chunk.string_pool.get(id as usize))
                    .map(|s| s.as_str())
                    .unwrap_or("-");
                let app = record
                    .app_name_id
                    .and_then(|id| chunk.string_pool.get(id as usize))
                    .map(|s| s.as_str())
                    .unwrap_or("-");
                let proc = record
                    .procid_id
                    .and_then(|id| chunk.string_pool.get(id as usize))
                    .map(|s| s.as_str())
                    .unwrap_or("-");
                let msgid = record
                    .msgid_id
                    .and_then(|id| chunk.string_pool.get(id as usize))
                    .map(|s| s.as_str())
                    .unwrap_or("-");
                let sd = record
                    .structured_data_id
                    .and_then(|id| chunk.string_pool.get(id as usize))
                    .map(|s| s.as_str())
                    .unwrap_or("-");

                if let Some(f) = &filter_lower {
                    let hay = format!(
                        "{} {} {} {} {} {} {}",
                        host, app, proc, msgid, sd, reconstructed, record.priority
                    )
                    .to_lowercase();
                    if !hay.contains(f) {
                        continue;
                    }
                }

                if let Some(dt) = Utc.timestamp_millis_opt(record.timestamp).earliest() {
                    let res = if record.is_rfc5424 {
                        writeln!(
                            stdout,
                            "<{}>1 {} {} {} {} {} [{}] {}",
                            record.priority,
                            dt.to_rfc3339(),
                            host,
                            app,
                            proc,
                            msgid,
                            sd,
                            reconstructed
                        )
                    } else {
                        // RFC 3164
                        writeln!(
                            stdout,
                            "<{}>{} {} {}",
                            record.priority,
                            dt.format("%b %d %H:%M:%S"),
                            host,
                            reconstructed
                        )
                    };

                    if let Err(e) = res {
                        if e.kind() == io::ErrorKind::BrokenPipe {
                            return Ok(());
                        }
                        return Err(e.into());
                    }
                }
            }
        }
        Commands::Generate {
            addr,
            protocol,
            count,
        } => {
            if protocol == "udp" {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                for i in 0..count {
                    let msg = format!(
                        "<34>1 2023-10-11T22:14:15.003Z myhost myapp 1234 ID47 [exampleSDID@32473] User user{} failed login from IP 192.168.1.{}",
                        i, i
                    );
                    socket.send_to(msg.as_bytes(), &addr).await?;
                }
            } else {
                let mut stream = tokio::net::TcpStream::connect(&addr).await?;
                for i in 0..count {
                    let msg = format!(
                        "<34>1 2023-10-11T22:14:15.003Z myhost myapp 1234 ID47 [exampleSDID@32473] User user{} failed login from IP 192.168.1.{}\n",
                        i, i
                    );
                    stream.write_all(msg.as_bytes()).await?;
                }
            }
            info!("Generated {} messages to {}", count, addr);
        }
        Commands::Bench { count, output } => {
            info!("Starting storage benchmark with {} logs...", count);
            let mut raw_size = 0;
            let mut chunk = LogChunk::new();
            let mut total_chunks_saved = 0;

            // Remove existing bench file if any
            let _ = std::fs::remove_file(&output);

            for i in 0..count {
                let msg_str = format!(
                    "<34>1 2023-10-11T22:14:15.003Z myhost myapp {} ID47 [exampleSDID@32473] User {} failed login from IP 192.168.1.{}",
                    1000 + (i % 10),
                    if i % 2 == 0 { "alice" } else { "bob" },
                    i % 255
                );
                raw_size += msg_str.len();

                if let Ok(msg) = UnifiedParser::parse(&msg_str) {
                    chunk.add_message(msg);
                }

                if (i + 1) % 1000 == 0 {
                    chunk.finish_and_process();
                    StorageEngine::save_chunk(chunk, &output)?;
                    chunk = LogChunk::new();
                    total_chunks_saved += 1;
                }
            }

            if !chunk.raw_messages.is_empty() {
                chunk.finish_and_process();
                StorageEngine::save_chunk(chunk, &output)?;
                total_chunks_saved += 1;
            }

            let compressed_size = std::fs::metadata(&output)?.len();

            println!("\nBenchmark Results:");
            println!("------------------");
            println!("Log Count:        {}", count);
            println!("Raw Text Size:    {:.2} MB", raw_size as f64 / 1_048_576.0);
            println!(
                "LogShrink Size:   {:.2} MB",
                compressed_size as f64 / 1_048_576.0
            );
            println!(
                "Reduction Ratio:  {:.2}x",
                raw_size as f64 / compressed_size as f64
            );
            println!(
                "Space Savings:    {:.1}%",
                (1.0 - (compressed_size as f64 / raw_size as f64)) * 100.0
            );
            println!("Chunks Saved:     {}", total_chunks_saved);
        }
    }

    Ok(())
}
