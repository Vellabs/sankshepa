use axum::{
    Router,
    extract::State,
    response::sse::{Event, Sse},
    routing::get,
};
use futures_util::stream::Stream;
use sankshepa_protocol::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tokio::sync::broadcast;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum UiMessage {
    Log(SyslogMessage),
    Stats {
        template_count: u32,
        log_count: usize,
        variable_count: usize,
        original_size: u64,
        compressed_size: u64,
    },
}

pub struct UiServer {
    tx: broadcast::Sender<UiMessage>,
}

impl UiServer {
    pub fn new(tx: broadcast::Sender<UiMessage>) -> Self {
        Self { tx }
    }

    pub async fn run(self, addr: &str) -> anyhow::Result<()> {
        let app = Router::new()
            .route("/", get(index))
            .route("/events", get(sse_handler))
            .with_state(self.tx);

        info!("UI server started on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn index() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("index.html"))
}

async fn sse_handler(
    State(tx): State<broadcast::Sender<UiMessage>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    info!("New SSE subscriber connected");
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(m) => {
            let json = serde_json::to_string(&m).ok()?;
            Some(Ok(Event::default().data(json)))
        }
        Err(_) => None,
    });

    Sse::new(stream)
}
