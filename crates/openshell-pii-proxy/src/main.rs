mod health;
mod policy;
mod proxy;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser)]
#[command(name = "pii-policy-proxy", about = "HTTP reverse proxy with PII detection")]
struct Args {
    /// Port to listen on.
    #[arg(long, env = "PII_PROXY_PORT", default_value = "9002")]
    port: u16,

    /// Upstream URL (the inference transform proxy).
    #[arg(long, env = "PII_UPSTREAM_URL", default_value = "http://127.0.0.1:9001")]
    upstream_url: String,

    /// Path to the PII policy YAML file. If absent, starts in passthrough mode.
    #[arg(long, env = "PII_POLICY_PATH")]
    policy_path: Option<PathBuf>,

    /// Path to the events JSONL file for telemetry integration.
    #[arg(long, env = "PII_EVENTS_PATH", default_value = "/sandbox/.nemoclaw/events.jsonl")]
    events_path: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let upstream = args.upstream_url.trim_end_matches('/').to_string();

    // Load PII engine (or start in passthrough mode).
    let engine = policy::init_engine(args.policy_path.as_deref());

    // Spawn hot-reload watcher if a policy path is configured.
    if let Some(ref path) = args.policy_path {
        policy::spawn_watcher(path.clone(), engine.clone());
    }

    // Build upstream HTTP client.
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();

    let state = Arc::new(proxy::ProxyState {
        engine,
        upstream_url: upstream.clone(),
        events_path: Some(args.events_path),
        client,
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = TcpListener::bind(addr).await.expect("Failed to bind");
    info!(port = args.port, upstream = %upstream, "PII policy proxy listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Accept failed");
                continue;
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let state = state.clone();
                async move {
                    // Route /healthz to health handler.
                    if req.uri().path() == "/healthz" {
                        return Ok::<_, hyper::Error>(health::handle());
                    }
                    proxy::handle(state, req).await
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                if !e.to_string().contains("connection closed") {
                    tracing::error!(error = %e, "Connection error");
                }
            }
        });
    }
}
