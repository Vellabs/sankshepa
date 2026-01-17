use crate::protocol::{SyslogMessage, UnifiedParser};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

pub struct IngestionServer {
    udp_addr: String,
    tcp_addr: String,
    beep_addr: String,
    tx: mpsc::Sender<SyslogMessage>,
}

impl IngestionServer {
    pub fn new(
        udp_addr: String,
        tcp_addr: String,
        beep_addr: String,
        tx: mpsc::Sender<SyslogMessage>,
    ) -> Self {
        Self {
            udp_addr,
            tcp_addr,
            beep_addr,
            tx,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tokio::try_join!(
            Self::run_udp(self.udp_addr, self.tx.clone()),
            Self::run_tcp(self.tcp_addr, self.tx.clone()),
            Self::run_beep(self.beep_addr, self.tx)
        )?;
        Ok(())
    }

    async fn run_beep(addr: String, _tx: mpsc::Sender<SyslogMessage>) -> anyhow::Result<()> {
        println!("BEEP listener (RFC 3195) started on {} [STUB]", addr);
        // BEEP implementation would go here.
        // For now, we just keep the port open.
        let listener = TcpListener::bind(&addr).await?;
        loop {
            let _ = listener.accept().await?;
        }
    }

    async fn run_udp(addr: String, tx: mpsc::Sender<SyslogMessage>) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(&addr).await?;
        println!("UDP listener started on {}", addr);
        let mut buf = [0u8; 65535];

        loop {
            let (len, _) = socket.recv_from(&mut buf).await?;
            let data = String::from_utf8_lossy(&buf[..len]);
            if let Ok(msg) = UnifiedParser::parse(&data) {
                let _ = tx.send(msg).await;
            }
        }
    }

    async fn run_tcp(addr: String, tx: mpsc::Sender<SyslogMessage>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&addr).await?;
        println!("TCP listener started on {}", addr);

        loop {
            let (socket, _) = listener.accept().await?;
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(socket);

                loop {
                    let mut first_byte = [0u8; 1];
                    if reader.read_exact(&mut first_byte).await.is_err() {
                        break;
                    }

                    if first_byte[0].is_ascii_digit() {
                        // Octet Counting
                        let mut len_bytes = vec![first_byte[0]];
                        loop {
                            let mut b = [0u8; 1];
                            if reader.read_exact(&mut b).await.is_err() {
                                break;
                            }
                            if b[0] == b' ' {
                                break;
                            }
                            len_bytes.push(b[0]);
                        }
                        if let Some(len) = String::from_utf8(len_bytes)
                            .ok()
                            .and_then(|s| s.parse::<usize>().ok())
                        {
                            let mut msg_buf = vec![0u8; len];
                            if reader.read_exact(&mut msg_buf).await.is_ok() {
                                let data = String::from_utf8_lossy(&msg_buf);
                                if let Ok(msg) = UnifiedParser::parse(&data) {
                                    let _ = tx_clone.send(msg).await;
                                }
                            }
                        }
                    } else if first_byte[0] == b'<' {
                        // Non-Transparent Framing (likely starting with <PRI>)
                        // Read until LF
                        let mut msg_bytes = vec![first_byte[0]];
                        let mut line = Vec::new();
                        use tokio::io::AsyncBufReadExt;
                        if reader.read_until(b'\n', &mut line).await.is_ok() {
                            msg_bytes.extend(line);
                            let data = String::from_utf8_lossy(&msg_bytes);
                            if let Ok(msg) = UnifiedParser::parse(data.trim_end()) {
                                let _ = tx_clone.send(msg).await;
                            }
                        }
                    } else if first_byte[0] == b'\n' || first_byte[0] == b'\r' {
                        // Skip empty lines
                        continue;
                    } else {
                        // Just consume the rest of the line if it's junk
                        let mut junk = Vec::new();
                        use tokio::io::AsyncBufReadExt;
                        let _ = reader.read_until(b'\n', &mut junk).await;
                    }
                }
            });
        }
    }
}
