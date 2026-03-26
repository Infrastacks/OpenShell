use crate::policy::SharedEngine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use openshell_pii::{PiiAction, PiiApplyResult, PiiDetection};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// Maximum body size we'll buffer (hard cap, independent of policy).
const MAX_BODY_CAP: usize = 4 * 1024 * 1024; // 4 MiB

/// State shared across all request handlers.
pub struct ProxyState {
    pub engine: SharedEngine,
    pub upstream_url: String,
    pub events_path: Option<PathBuf>,
    pub client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
}

/// Handle an incoming HTTP request: scan for PII, then forward or block.
pub async fn handle(
    state: Arc<ProxyState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_default();
    let headers = req.headers().clone();

    // Collect request body.
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to read request body");
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Failed to read request body"));
        }
    };

    if body_bytes.len() > MAX_BODY_CAP {
        // Body too large — pass through without scanning.
        return forward(&state, method, &path, &headers, body_bytes).await;
    }

    // PII scan.
    let mut body_vec = body_bytes.to_vec();
    let (scan_result, detections) = {
        let guard = state.engine.read().unwrap();
        match guard.as_ref() {
            Some(engine) => {
                let dets = engine.detect(&body_vec);
                let result = engine.apply(&mut body_vec, &dets);
                (Some(result), dets)
            }
            None => (None, Vec::new()),
        }
    };

    match scan_result {
        None => {
            forward(&state, method, &path, &headers, body_bytes).await
        }
        Some(PiiApplyResult::Clean) => {
            forward(&state, method, &path, &headers, body_bytes).await
        }
        Some(PiiApplyResult::Audited(ref _dets)) => {
            info!(
                engine = "pii",
                pii_action = "audit",
                pii_entities_found = detections.len(),
                policy = "pii-policy",
                "PII_DETECTION"
            );
            emit_events(&state, &detections, "audit");
            forward(&state, method, &path, &headers, body_bytes).await
        }
        Some(PiiApplyResult::Redacted { count, .. }) => {
            info!(
                engine = "pii",
                pii_action = "redact",
                pii_redaction_count = count,
                policy = "pii-policy",
                "PII_DETECTION"
            );
            emit_events(&state, &detections, "redact");
            forward(&state, method, &path, &headers, Bytes::from(body_vec)).await
        }
        Some(PiiApplyResult::Blocked { .. }) => {
            info!(
                engine = "pii",
                pii_action = "block",
                policy = "pii-policy",
                "PII_DETECTION"
            );
            emit_events(&state, &detections, "block");
            Ok(error_response(
                StatusCode::FORBIDDEN,
                r#"{"error":{"message":"Request blocked: PII detected in request body","type":"pii_policy_violation","code":"pii_blocked"}}"#,
            ))
        }
    }
}

/// Forward a request to the upstream server.
async fn forward(
    state: &ProxyState,
    method: hyper::Method,
    path: &str,
    headers: &hyper::HeaderMap,
    body: Bytes,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = format!("{}{}", state.upstream_url, path);
    let mut builder = Request::builder().method(method).uri(&uri);

    // Copy headers, skip host (will be set by hyper).
    for (key, value) in headers.iter() {
        if key != hyper::header::HOST {
            builder = builder.header(key, value);
        }
    }

    // Update Content-Length if body was modified (redacted).
    builder = builder.header(hyper::header::CONTENT_LENGTH, body.len());

    let upstream_req = builder.body(Full::new(body)).unwrap();

    match state.client.request(upstream_req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();
            let resp_body = resp.collect().await.map(|c| c.to_bytes()).unwrap_or_default();

            let mut response = Response::builder().status(status);
            for (key, value) in resp_headers.iter() {
                response = response.header(key, value);
            }
            Ok(response.body(Full::new(resp_body)).unwrap())
        }
        Err(e) => {
            tracing::error!(error = %e, uri = %uri, "Upstream request failed");
            Ok(error_response(StatusCode::BAD_GATEWAY, &format!("Upstream error: {e}")))
        }
    }
}

fn error_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Write per-entity PII detection events to the events JSONL file.
/// Each entity gets its own line so the dashboard can aggregate by entityType.
fn emit_events(state: &ProxyState, detections: &[PiiDetection], default_action: &str) {
    let Some(ref path) = state.events_path else { return };

    let mut file = match OpenOptions::new().append(true).create(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to open events file");
            return;
        }
    };

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Deduplicate by entity type — emit one event per unique entity type.
    let mut seen = std::collections::HashSet::new();
    for det in detections {
        if !seen.insert(det.entity_type) {
            continue;
        }

        // Resolve the action for this specific entity from the engine's policy.
        let action = {
            let guard = state.engine.read().unwrap();
            guard.as_ref().map_or_else(
                || default_action.to_string(),
                |engine| match engine.policy().action_for(det.entity_type) {
                    PiiAction::Redact => "redact".to_string(),
                    PiiAction::Block => "block".to_string(),
                    PiiAction::Warn => "audit".to_string(),
                    PiiAction::Audit => "audit".to_string(),
                },
            )
        };

        let event_type = match action.as_str() {
            "block" => "pii.blocked",
            "redact" => "pii.redacted",
            _ => "pii.detected",
        };

        let line = format!(
            r#"{{"eventType":"{}","timestamp":"{}","data":{{"entityType":"{}","action":"{}","engine":"pii","direction":"request"}}}}"#,
            event_type, now, det.entity_type, action,
        );

        if let Err(e) = writeln!(file, "{}", line) {
            tracing::warn!(error = %e, "Failed to write PII event");
        }
    }
}
