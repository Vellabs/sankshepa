mod ingestion;
mod protocol;
mod storage;

use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use ingestion::IngestionServer;
use storage::StorageEngine;
use storage::logshrink::LogChunk;
use tokio::sync::mpsc;

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
        #[arg(long, default_value = "logs.lshrink")]
        output: String,
    },
    /// Extracts and reconstructs logs from LogShrink storage
    Query {
        #[arg(long, default_value = "logs.lshrink")]
        input: String,
        #[arg(long)]
        template_id: Option<u32>,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            udp_addr,
            tcp_addr,
            beep_addr,
            output,
        } => {
            let (tx, mut rx) = mpsc::channel(100);
            let server = IngestionServer::new(udp_addr, tcp_addr, beep_addr, tx);

            let output_path = output.clone();
            let server_handle = tokio::spawn(async move {
                let mut chunk = LogChunk::new();
                let mut count = 0;
                loop {
                    tokio::select! {
                        Some(msg) = rx.recv() => {
                            chunk.add_message(msg);
                            count += 1;
                            if count >= 10 {
                                chunk.finish_and_process();
                                let _ = StorageEngine::save_chunk(chunk, &output_path);
                                chunk = LogChunk::new();
                                count = 0;
                                println!("Saved chunk to {}", output_path);
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            if count > 0 {
                                chunk.finish_and_process();
                                let _ = StorageEngine::save_chunk(chunk, &output_path);
                                println!("Saved final chunk on Ctrl-C");
                            }
                            break;
                        }
                    }
                }
            });

            tokio::select! {
                res = server.run() => {
                    if let Err(e) = res {
                        eprintln!("Server error: {}", e);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    // Let the server_handle finish its work
                }
            }
            let _ = server_handle.await;
        }
        Commands::Query { input, template_id } => {
            let chunk = StorageEngine::load_chunk(&input)?;

            let mut pattern_map = std::collections::HashMap::new();
            for (pattern, &id) in &chunk.templates {
                pattern_map.insert(id, pattern.clone());
            }

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

                if let Some(dt) = Utc.timestamp_millis_opt(record.timestamp).earliest() {
                    let host = record.hostname.as_deref().unwrap_or("-");
                    let app = record.app_name.as_deref().unwrap_or("-");
                    let proc = record.procid.as_deref().unwrap_or("-");
                    let msgid = record.msgid.as_deref().unwrap_or("-");
                    let sd = record.structured_data.as_deref().unwrap_or("-");

                    if record.is_rfc5424 {
                        println!(
                            "<{}>1 {} {} {} {} {} [{}] {}",
                            record.priority,
                            dt.to_rfc3339(),
                            host,
                            app,
                            proc,
                            msgid,
                            sd,
                            reconstructed
                        );
                    } else {
                        // RFC 3164
                        println!(
                            "<{}>{} {} {}",
                            record.priority,
                            dt.format("%b %d %H:%M:%S"),
                            host,
                            reconstructed
                        );
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
                use tokio::io::AsyncWriteExt;
                for i in 0..count {
                    let msg = format!(
                        "<34>1 2023-10-11T22:14:15.003Z myhost myapp 1234 ID47 [exampleSDID@32473] User user{} failed login from IP 192.168.1.{}\n",
                        i, i
                    );
                    stream.write_all(msg.as_bytes()).await?;
                }
            }
            println!("Generated {} messages to {}", count, addr);
        }
    }

    Ok(())
}
