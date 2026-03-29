// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::provider::L7Provider;
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::secrets::SecretResolver;
use miette::{IntoDiagnostic, Result, miette};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

/// Context for L7 request policy evaluation.
pub struct L7EvalContext {
    /// Host from the CONNECT request.
    pub host: String,
    /// Port from the CONNECT request.
    pub port: u16,
    /// Matched policy name from L4 evaluation.
    pub policy_name: String,
    /// Binary path (for cross-layer Rego evaluation).
    pub binary_path: String,
    /// Ancestor paths.
    pub ancestors: Vec<String>,
    /// Cmdline paths.
    pub cmdline_paths: Vec<String>,
    /// Supervisor-only placeholder resolver for outbound headers.
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
    /// PII detection engine (None = PII scanning disabled).
    pub pii_engine: Option<openshell_pii::PiiEngine>,
    /// Supply chain engine (None = supply chain scanning disabled).
    pub supply_chain_engine: Option<openshell_supply_chain::SupplyChainEngine>,
    /// Path to events.jsonl for emitting telemetry events (shared with PII proxy + agent tailer).
    pub events_path: Option<PathBuf>,
}

/// Run protocol-aware L7 inspection on a tunnel.
///
/// This replaces `copy_bidirectional` for L7-enabled endpoints.
/// Protocol detection (peek) is the caller's responsibility — this function
/// assumes the streams are already proven to carry the expected protocol.
/// For TLS-terminated connections, ALPN proves HTTP; for plaintext, the
/// caller peeks on the raw `TcpStream` before calling this.
pub async fn relay_with_inspection<C, U>(
    config: &L7EndpointConfig,
    engine: Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &mut L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match config.protocol {
        L7Protocol::Rest => relay_rest(config, &engine, client, upstream, ctx).await,
        L7Protocol::Sql => {
            // SQL provider is Phase 3 — fall through to passthrough with warning
            warn!(
                host = %ctx.host,
                port = ctx.port,
                "SQL L7 provider not yet implemented, falling back to passthrough"
            );
            tokio::io::copy_bidirectional(client, upstream)
                .await
                .into_diagnostic()?;
            Ok(())
        }
    }
}

/// REST relay loop: parse request -> evaluate -> allow/deny -> relay response -> repeat.
async fn relay_rest<C, U>(
    config: &L7EndpointConfig,
    engine: &Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &mut L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        // Parse one HTTP request from client
        let req = match crate::l7::rest::RestProvider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // Client closed connection
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 connection closed"
                    );
                } else {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "HTTP parse error in L7 relay"
                    );
                }
                return Ok(()); // Close connection on parse error
            }
        };

        // --- Supply chain check (URL-based, before OPA eval) ---
        if let Some(sc_engine) = ctx.supply_chain_engine.as_mut() {
            if let Some(registry_match) =
                openshell_supply_chain::detect_registry_pattern(&ctx.host, &req.target)
            {
                let result = sc_engine.evaluate(&registry_match).await;
                info!(
                    engine = "supply_chain",
                    ecosystem = %registry_match.ecosystem,
                    package = %registry_match.package,
                    version = %registry_match.version,
                    decision = %result.decision,
                    vuln_critical = result.vuln_counts.critical,
                    vuln_high = result.vuln_counts.high,
                    "PACKAGE_INSTALL"
                );

                // Emit events.jsonl for agent telemetry pipeline (async I/O)
                if let Some(ref events_path) = ctx.events_path {
                    let event_type = if result.decision == openshell_supply_chain::Decision::Deny {
                        "package.blocked"
                    } else {
                        "package.install"
                    };
                    let decision_str = match result.decision {
                        openshell_supply_chain::Decision::Allow => "allow",
                        openshell_supply_chain::Decision::Audit => "audit",
                        openshell_supply_chain::Decision::Deny => "deny",
                    };
                    let license_status = match result.license_status {
                        openshell_supply_chain::LicenseStatus::Allowed => "allowed",
                        openshell_supply_chain::LicenseStatus::Denied => "denied",
                        openshell_supply_chain::LicenseStatus::Unknown => "unknown",
                    };
                    let now = crate::l7::utc_now_rfc3339();
                    let event = serde_json::json!({
                        "eventType": event_type,
                        "timestamp": now,
                        "data": {
                            "ecosystem": registry_match.ecosystem,
                            "packageName": registry_match.package,
                            "version": registry_match.version,
                            "decision": decision_str,
                            "vulnCountCritical": result.vuln_counts.critical,
                            "vulnCountHigh": result.vuln_counts.high,
                            "licenseStatus": license_status,
                            "denialReason": result.denial_reason.as_deref().unwrap_or(""),
                        }
                    });
                    let vuln_events: Vec<serde_json::Value> = result
                        .vulnerabilities
                        .iter()
                        .map(|vuln| {
                            serde_json::json!({
                                "eventType": "package.vulnerability",
                                "timestamp": &now,
                                "data": {
                                    "ecosystem": registry_match.ecosystem,
                                    "packageName": registry_match.package,
                                    "version": registry_match.version,
                                    "osvId": vuln.osv_id,
                                    "severity": vuln.severity,
                                    "summary": vuln.summary,
                                    "fixedVersion": vuln.fixed_version.as_deref().unwrap_or(""),
                                }
                            })
                        })
                        .collect();
                    emit_supply_chain_events(events_path, &event, &vuln_events).await;
                }

                if result.decision == openshell_supply_chain::Decision::Deny {
                    let reason = result.denial_reason.unwrap_or_default();
                    crate::l7::rest::RestProvider
                        .deny(&req, &ctx.policy_name, &reason, client)
                        .await?;
                    return Ok(());
                }
            }
        }

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: req.target.clone(),
        };

        // Evaluate L7 policy via Rego
        let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;

        let decision_str = match (allowed, config.enforcement) {
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };

        // Log every L7 decision
        info!(
            dst_host = %ctx.host,
            dst_port = ctx.port,
            policy = %ctx.policy_name,
            l7_protocol = "rest",
            l7_action = %request_info.action,
            l7_target = %request_info.target,
            l7_decision = decision_str,
            l7_deny_reason = %reason,
            "L7_REQUEST",
        );

        if allowed || config.enforcement == EnforcementMode::Audit {
            // --- PII scan on request body (Tier 1: regex) ---
            if let Some(ref pii_engine) = ctx.pii_engine {
                let pii_result = crate::l7::rest::relay_http_request_with_pii(
                    &req,
                    client,
                    upstream,
                    ctx.secret_resolver.as_deref(),
                    pii_engine,
                )
                .await?;

                match &pii_result {
                    crate::l7::rest::PiiRelayResult::Blocked(entity_types) => {
                        info!(
                            dst_host = %ctx.host,
                            dst_port = ctx.port,
                            policy = %ctx.policy_name,
                            engine = "pii",
                            pii_action = "block",
                            "PII_DETECTION"
                        );
                        emit_pii_event(ctx, "pii.blocked", "block", entity_types.len(), entity_types).await;
                        crate::l7::rest::RestProvider
                            .deny(
                                &req,
                                &ctx.policy_name,
                                "Request blocked: PII detected in body",
                                client,
                            )
                            .await?;
                        return Ok(());
                    }
                    crate::l7::rest::PiiRelayResult::Redacted(count, entity_types) => {
                        info!(
                            dst_host = %ctx.host,
                            dst_port = ctx.port,
                            policy = %ctx.policy_name,
                            engine = "pii",
                            pii_action = "redact",
                            pii_redaction_count = count,
                            "PII_DETECTION"
                        );
                        emit_pii_event(ctx, "pii.redacted", "redact", *count, entity_types).await;
                    }
                    crate::l7::rest::PiiRelayResult::Audited(count, entity_types) => {
                        info!(
                            dst_host = %ctx.host,
                            dst_port = ctx.port,
                            policy = %ctx.policy_name,
                            engine = "pii",
                            pii_action = "audit",
                            pii_entities_found = count,
                            "PII_DETECTION"
                        );
                        emit_pii_event(ctx, "pii.detection", "audit", *count, entity_types).await;
                    }
                    crate::l7::rest::PiiRelayResult::Clean => {}
                }
            } else {
                // No PII engine — relay without scanning.
                let reusable = crate::l7::rest::relay_http_request_with_resolver(
                    &req,
                    client,
                    upstream,
                    ctx.secret_resolver.as_deref(),
                )
                .await?;
                if !reusable {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing L7 relay"
                    );
                    return Ok(());
                }
            }
        } else {
            // Enforce mode: deny with 403 and close connection
            crate::l7::rest::RestProvider
                .deny(&req, &ctx.policy_name, &reason, client)
                .await?;
            return Ok(());
        }
    }
}

/// Check if a miette error represents a benign connection close.
///
/// TLS handshake EOF, missing `close_notify`, connection resets, and broken
/// pipes are all normal lifecycle events for proxied connections — not worth
/// a WARN that interrupts the user's terminal.
fn is_benign_connection_error(err: &miette::Report) -> bool {
    const BENIGN: &[&str] = &[
        "close_notify",
        "tls handshake eof",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "client disconnected mid-request",
    ];
    let msg = err.to_string().to_ascii_lowercase();
    BENIGN.iter().any(|pat| msg.contains(pat))
}

/// Evaluate an L7 request against the OPA engine.
///
/// Returns `(allowed, deny_reason)`.
fn evaluate_l7_request(
    engine: &Mutex<regorus::Engine>,
    ctx: &mut L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    let input_json = serde_json::json!({
        "network": {
            "host": ctx.host,
            "port": ctx.port,
        },
        "exec": {
            "path": ctx.binary_path,
            "ancestors": ctx.ancestors,
            "cmdline_paths": ctx.cmdline_paths,
        },
        "request": {
            "method": request.action,
            "path": request.target,
        }
    });

    let mut engine = engine
        .lock()
        .map_err(|_| miette!("OPA engine lock poisoned"))?;

    engine
        .set_input_json(&input_json.to_string())
        .map_err(|e| miette!("{e}"))?;

    let allowed = engine
        .eval_rule("data.openshell.sandbox.allow_request".into())
        .map_err(|e| miette!("{e}"))?;
    let allowed = allowed == regorus::Value::from(true);

    let reason = if allowed {
        String::new()
    } else {
        let val = engine
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .map_err(|e| miette!("{e}"))?;
        match val {
            regorus::Value::String(s) => s.to_string(),
            regorus::Value::Undefined => "request denied by policy".to_string(),
            other => other.to_string(),
        }
    };

    Ok((allowed, reason))
}

/// Emit a PII detection event to events.jsonl (async I/O).
async fn emit_pii_event(
    ctx: &L7EvalContext,
    event_type: &str,
    action: &str,
    entity_count: usize,
    entity_types: &[String],
) {
    let Some(ref events_path) = ctx.events_path else {
        return;
    };
    let now = crate::l7::utc_now_rfc3339();
    let event = serde_json::json!({
        "eventType": event_type,
        "timestamp": now,
        "data": {
            "action": action,
            "entityCount": entity_count,
            "entityTypes": entity_types,
            "host": ctx.host,
            "port": ctx.port,
        }
    });
    let line = format!("{event}\n");
    let path = events_path.clone();
    // Write on a blocking thread to avoid stalling the async runtime.
    let _ = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    })
    .await;
}

/// Emit supply chain events to events.jsonl (async I/O).
async fn emit_supply_chain_events(
    events_path: &std::path::Path,
    event_json: &serde_json::Value,
    vuln_events: &[serde_json::Value],
) {
    let mut lines = String::new();
    use std::fmt::Write;
    let _ = writeln!(lines, "{event_json}");
    for v in vuln_events {
        let _ = writeln!(lines, "{v}");
    }
    let path = events_path.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(lines.as_bytes());
        }
    })
    .await;
}
