mod node;

use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use node::{Node, NodeConfig};
use sankshepa_protocol::UnifiedParser;
use sankshepa_storage::StorageEngine;
use sankshepa_storage::logshrink::LogChunk;
use std::io::{self, BufRead, Write};
use tokio::io::AsyncWriteExt;
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
        /// Unique node identifier
        #[arg(long)]
        node_id: Option<String>,
        /// Cluster management address (UDP)
        #[arg(long, default_value = "127.0.0.1:1701")]
        cluster_addr: String,
        /// Initial peer addresses
        #[arg(long)]
        peers: Vec<String>,
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
        #[arg(long, default_value = "0.0.0.0:1514")]
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
        #[arg(long, default_value = "low")]
        entropy: String,
        /// Input log file or directory to benchmark against (disables synthetic generation)
        #[arg(long)]
        input: Option<String>,
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
            node_id,
            cluster_addr,
            peers,
        } => {
            let node_id = node_id.unwrap_or_else(|| format!("node-{}", std::process::id()));
            let config = NodeConfig {
                udp_addr,
                tcp_addr,
                beep_addr,
                ui_addr,
                output_path: output,
                node_id,
                cluster_addr,
                peers,
            };

            let node = Node::new(config)?;
            node.run().await?;
        }
        Commands::Query {
            input,
            template_id,
            filter,
        } => {
            query_logs(&input, template_id, filter.as_deref())?;
        }
        Commands::Generate {
            addr,
            protocol,
            count,
        } => {
            generate_logs(&addr, &protocol, count).await?;
        }
        Commands::Bench {
            count,
            output,
            entropy,
            input,
        } => {
            run_benchmark(count, &output, &entropy, input)?;
        }
    }

    Ok(())
}

fn query_logs(input: &str, template_id: Option<u32>, filter: Option<&str>) -> anyhow::Result<()> {
    let mut paths = Vec::new();
    let input_path = std::path::Path::new(input);

    if input_path.is_dir() {
        for entry in walkdir::WalkDir::new(input_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file()
                && entry.path().extension().is_some_and(|ext| ext == "lshrink")
            {
                paths.push(entry.path().to_path_buf());
            }
        }
    } else {
        paths.push(std::path::PathBuf::from(input));
    }

    let filter_lower = filter.map(|s| s.to_lowercase());
    let mut stdout = io::stdout().lock();

    for path in paths {
        let chunk = match StorageEngine::load_chunk(&path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to load chunk at {:?}: {}", path, e);
                continue;
            }
        };

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
            let mut reconstructed = pattern;
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
            let node = record
                .node_id_id
                .and_then(|id| chunk.string_pool.get(id as usize))
                .map(|s| s.as_str())
                .unwrap_or("-");

            if let Some(f) = &filter_lower {
                let hay = format!(
                    "{} {} {} {} {} {} {} {}",
                    host, app, proc, msgid, sd, reconstructed, record.priority, node
                )
                .to_lowercase();
                if !hay.contains(f) {
                    continue;
                }
            }

            if let Some(dt) = Utc.timestamp_millis_opt(record.timestamp).earliest() {
                if record.is_rfc5424 {
                    writeln!(
                        stdout,
                        "[{}] <{}>1 {} {} {} {} {} [{}] {}",
                        node,
                        record.priority,
                        dt.to_rfc3339(),
                        host,
                        app,
                        proc,
                        msgid,
                        sd,
                        reconstructed
                    )?;
                } else {
                    writeln!(
                        stdout,
                        "[{}] <{}>{} {} {}",
                        node,
                        record.priority,
                        dt.format("%b %d %H:%M:%S"),
                        host,
                        reconstructed
                    )?;
                }
            }
        }
    }
    Ok(())
}

async fn generate_logs(addr: &str, protocol: &str, count: usize) -> anyhow::Result<()> {
    if protocol == "udp" {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        for i in 0..count {
            let msg = format!(
                "<34>1 2023-10-11T22:14:15.003Z myhost myapp 1234 ID47 [exampleSDID@32473] User user{} failed login from IP 192.168.1.{}",
                i, i
            );
            let _ = socket.send_to(msg.as_bytes(), addr).await;
        }
    } else {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        for i in 0..count {
            let msg = format!(
                "<34>1 2023-10-11T22:14:15.003Z myhost myapp 1234 ID47 [exampleSDID@32473] User user{} failed login from IP 192.168.1.{}\n",
                i, i
            );
            let _ = stream.write_all(msg.as_bytes()).await;
        }
    }
    info!("Generated {} messages to {}", count, addr);
    Ok(())
}

fn run_benchmark(
    count: usize,
    output: &str,
    entropy_str: &str,
    input_path: Option<String>,
) -> anyhow::Result<()> {
    info!(
        "Starting storage benchmark (mode: {})...",
        if let Some(ref p) = input_path {
            format!("file: {}", p)
        } else {
            format!("synthetic: {}", entropy_str)
        }
    );
    let mut raw_size = 0;
    let mut chunk = LogChunk::new();
    let mut total_chunks_saved = 0;
    let mut all_raw_logs = Vec::new();

    let _ = std::fs::remove_file(output);

    let messages: Vec<String> = if let Some(ref path) = input_path {
        let mut lines = Vec::new();
        let path_obj = std::path::Path::new(&path);
        let paths = if path_obj.is_dir() {
            std::fs::read_dir(path_obj)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .map(|e| e.path())
                .collect()
        } else {
            vec![path_obj.to_path_buf()]
        };

        for p in paths {
            let file = std::fs::File::open(p)?;
            let reader = std::io::BufReader::new(file);
            for l in reader.lines().map_while(Result::ok) {
                if !l.trim().is_empty() {
                    lines.push(l);
                }
            }
        }
        lines
    } else {
        let mut msgs = Vec::with_capacity(count);
        for i in 0..count {
            let msg_str = match entropy_str {
                "low" => format!(
                    "<34>1 2023-10-11T22:14:15.003Z myhost myapp {} ID47 [exampleSDID@32473] User {} failed at login from IP 192.168.1.{}",
                    1000 + (i % 10),
                    if i % 2 == 0 { "alice" } else { "bob" },
                    i % 255
                ),
                "mixed" => {
                    if i % 10 == 0 {
                        format!(
                            "<34>1 2023-10-11T22:14:15.003Z host{} app{} {} ID{} [sd@1] Random event {}",
                            i % 5,
                            i % 3,
                            i,
                            i % 100,
                            i
                        )
                    } else {
                        format!(
                            "<34>1 2023-10-11T22:14:15.003Z myhost myapp {} ID47 [exampleSDID@32473] User {} failed at login from IP 192.168.1.{}",
                            1000 + (i % 10),
                            if i % 2 == 0 { "alice" } else { "bob" },
                            i % 255
                        )
                    }
                }
                "high" => format!(
                    "<34>1 2023-10-11T22:14:15.003Z host{} app{} {} ID{} [sd@{}] Unusual message containing random salt {}",
                    i,
                    i,
                    i,
                    i,
                    i,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_nanos()
                        % 1000000
                ),
                "loghub" => match i % 3 {
                    0 => format!(
                        "<34>1 2023-10-11T22:14:15.003Z hdfs_node{} datanode {} ID{} [sd@1] Receiving block blk_-{} src: /192.168.1.{} dest: /192.168.1.{}",
                        i % 10,
                        1000 + (i % 5),
                        i % 100,
                        i % 500,
                        i % 255,
                        (i + 1) % 255
                    ),
                    1 => format!(
                        "<34>1 2023-10-11T22:14:15.003Z bgl_node{} rts {} ID{} [sd@2] instruction cache parity error corrected: core.{} at address 0x{:08x}",
                        i % 100,
                        i % 50,
                        i % 200,
                        i % 4,
                        i * 4096
                    ),
                    _ => format!(
                        "<34>1 2023-10-11T22:14:15.003Z android_device{} ActivityManager {} ID{} [sd@3] START u0 {{act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10200000 cmp=com.android.{}/.{} }} from uid {}",
                        i % 20,
                        2000 + (i % 10),
                        i,
                        ["settings", "vending", "chrome", "calendar"][i % 4],
                        ["MainActivity", "HomeActivity", "Browser"][i % 3],
                        10000 + (i % 100)
                    ),
                },
                _ => return Err(anyhow::anyhow!("Unknown entropy level: {}", entropy_str)),
            };
            msgs.push(msg_str);
        }
        msgs
    };

    for (i, msg_str) in messages.iter().enumerate() {
        raw_size += msg_str.len();
        all_raw_logs.push(msg_str.clone());

        if let Ok(msg) = UnifiedParser::parse(msg_str) {
            chunk.add_message(msg);
        }

        if (i + 1) % 1000 == 0 {
            chunk.finish_and_process();
            StorageEngine::save_chunk(std::mem::take(&mut chunk), output)?;
            total_chunks_saved += 1;
        }
    }

    if !chunk.raw_messages.is_empty() {
        chunk.finish_and_process();
        StorageEngine::save_chunk(chunk, output)?;
        total_chunks_saved += 1;
    }

    let compressed_size = if std::path::Path::new(output).exists() {
        std::fs::metadata(output)?.len()
    } else {
        0
    };

    let raw_combined = all_raw_logs.join("\n");
    let raw_zstd = zstd::stream::encode_all(raw_combined.as_bytes(), 3)?;
    let raw_zstd_size = raw_zstd.len();

    println!("\nBenchmark Results:");
    println!("--------------------------------------");
    if let Some(path) = input_path {
        println!("Source:              {}", path);
    } else {
        println!("Entropy Level:       {}", entropy_str);
    }
    println!("Log Count:           {}", messages.len());
    println!(
        "Raw Text Size:       {:.2} MB",
        raw_size as f64 / 1_048_576.0
    );
    println!(
        "Raw + Zstd Size:     {:.2} MB ({:.2}x reduction)",
        raw_zstd_size as f64 / 1_048_576.0,
        raw_size as f64 / raw_zstd_size as f64
    );
    println!(
        "LogShrink Size:      {:.2} MB ({:.2}x reduction)",
        compressed_size as f64 / 1_048_576.0,
        if compressed_size > 0 {
            raw_size as f64 / compressed_size as f64
        } else {
            0.0
        }
    );
    println!(
        "Gains over Raw Zstd: {:.1}%",
        if raw_zstd_size > 0 {
            (1.0 - (compressed_size as f64 / raw_zstd_size as f64)) * 100.0
        } else {
            0.0
        }
    );
    println!("Chunks Saved:        {}", total_chunks_saved);

    Ok(())
}
