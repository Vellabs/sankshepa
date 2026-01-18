use axum::{
    Router,
    extract::State,
    response::sse::{Event, Sse},
    routing::get,
};
use futures_util::stream::Stream;
use sankshepa_protocol::SyslogMessage;
use std::convert::Infallible;
use tokio::sync::broadcast;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tracing::info;

pub struct UiServer {
    tx: broadcast::Sender<SyslogMessage>,
}

impl UiServer {
    pub fn new(tx: broadcast::Sender<SyslogMessage>) -> Self {
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
    State(tx): State<broadcast::Sender<SyslogMessage>>,
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
