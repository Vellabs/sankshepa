use sankshepa_protocol::{SyslogMessage, UnifiedParser};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct IngestionServer {
    udp_addr: String,
    tcp_addr: String,
    _beep_addr: String,
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
            _beep_addr: beep_addr,
            tx,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let udp = Self::run_udp(self.udp_addr, self.tx.clone());
        let tcp = Self::run_tcp(self.tcp_addr, self.tx.clone());

        tokio::try_join!(udp, tcp)?;
        Ok(())
    }

    async fn run_udp(addr: String, tx: mpsc::Sender<SyslogMessage>) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(&addr).await?;
        info!("UDP listener started on {}", addr);
        let mut buf = [0u8; 65535];

        loop {
            let (len, _) = socket.recv_from(&mut buf).await?;
            let data = String::from_utf8_lossy(&buf[..len]);
            let trimmed = data.trim();
            debug!("UDP received: {}", trimmed);

            if let Ok(msg) = UnifiedParser::parse(trimmed) {
                let _ = tx.send(msg).await;
            } else if !trimmed.is_empty() {
                warn!("Failed to parse UDP message: {}", trimmed);
            }
        }
    }

    async fn run_tcp(addr: String, tx: mpsc::Sender<SyslogMessage>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&addr).await?;
        info!("TCP listener started on {}", addr);

        loop {
            let (socket, _) = listener.accept().await?;
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                let mut reader = BufReader::new(socket);
                let _ = Self::handle_tcp_client(&mut reader, tx_clone).await;
            });
        }
    }

    async fn handle_tcp_client(
        reader: &mut BufReader<tokio::net::TcpStream>,
        tx: mpsc::Sender<SyslogMessage>,
    ) -> anyhow::Result<()> {
        loop {
            let mut first_byte = [0u8; 1];
            if reader.read_exact(&mut first_byte).await.is_err() {
                break;
            }

            match first_byte[0] {
                b'0'..=b'9' => {
                    // Octet Counting (RFC 6587)
                    if let Some(msg) = Self::read_octet_counted(reader, first_byte[0]).await? {
                        let _ = tx.send(msg).await;
                    }
                }
                b'<' => {
                    // Non-Transparent Framing
                    if let Some(msg) = Self::read_delimited(reader, first_byte[0]).await? {
                        let _ = tx.send(msg).await;
                    }
                }
                b'\n' | b'\r' => continue,
                _ => {
                    // Non-standard framing: Read until newline and attempt to parse
                    let mut line_buf = Vec::new();
                    line_buf.push(first_byte[0]);
                    let _ = reader.read_until(b'\n', &mut line_buf).await;
                    let data = String::from_utf8_lossy(&line_buf);
                    let trimmed = data.trim();
                    if !trimmed.is_empty() {
                        if let Ok(msg) = UnifiedParser::parse(trimmed) {
                            let _ = tx.send(msg).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn read_octet_counted(
        reader: &mut BufReader<tokio::net::TcpStream>,
        first_digit: u8,
    ) -> anyhow::Result<Option<SyslogMessage>> {
        let mut len_bytes = vec![first_digit];
        loop {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b).await?;
            if b[0] == b' ' {
                break;
            }
            len_digit(&mut len_bytes, b[0])?;
        }

        let len_str = String::from_utf8(len_bytes)?;
        let len = len_str.parse::<usize>()?;

        let mut msg_buf = vec![0u8; len];
        reader.read_exact(&mut msg_buf).await?;

        let data = String::from_utf8_lossy(&msg_buf);
        debug!("TCP (Octet) received: {}", data.trim());
        Ok(UnifiedParser::parse(&data).ok())
    }

    async fn read_delimited(
        reader: &mut BufReader<tokio::net::TcpStream>,
        first_char: u8,
    ) -> anyhow::Result<Option<SyslogMessage>> {
        let mut msg_bytes = vec![first_char];
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).await?;
        msg_bytes.extend(line);

        let data = String::from_utf8_lossy(&msg_bytes);
        debug!("TCP (Delimited) received: {}", data.trim());
        Ok(UnifiedParser::parse(data.trim()).ok())
    }
}

fn len_digit(len_bytes: &mut Vec<u8>, b: u8) -> anyhow::Result<()> {
    if b.is_ascii_digit() {
        len_bytes.push(b);
        Ok(())
    } else {
        Err(anyhow::anyhow!("Invalid digit in octet length"))
    }
}
