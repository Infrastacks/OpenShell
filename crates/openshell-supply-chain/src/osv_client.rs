// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OSV.dev API client with in-memory TTL cache, proxy bypass, and fail-closed
//! behaviour.
//!
//! Security hardening:
//! - **Proxy bypass**: the HTTP client is built with `no_proxy()` so OSV
//!   queries go direct, avoiding circular routing through the CONNECT proxy
//!   that embeds this engine.  Since the proxy is bypassed, the sandbox's
//!   ephemeral MITM CA is never involved — standard TLS verification uses
//!   the Mozilla/webpki root CA store compiled into rustls.
//! - **Fail-closed**: `query()` returns `Result`.  In `enforce` mode callers
//!   must deny the package when OSV is unreachable.
//! - **Response validation**: oversized or unparseable responses are rejected.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

/// Error returned when the OSV API query fails.
#[derive(Debug)]
pub enum OsvQueryError {
    /// Network / TLS / timeout error.
    Network(String),
    /// Response body too large.
    ResponseTooLarge(usize),
    /// Could not parse the JSON response.
    ParseError(String),
}

impl std::fmt::Display for OsvQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "OSV network error: {e}"),
            Self::ResponseTooLarge(size) => {
                write!(f, "OSV response too large: {size} bytes")
            }
            Self::ParseError(e) => write!(f, "OSV parse error: {e}"),
        }
    }
}

/// A vulnerability from OSV.dev.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    /// Database-specific metadata (e.g., GitHub Advisory severity label).
    #[serde(default)]
    pub database_specific: Option<DatabaseSpecific>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSpecific {
    /// Human-readable severity from the advisory database (e.g., "CRITICAL",
    /// "HIGH", "MODERATE", "LOW"). Used as fallback when CVSS vectors can't
    /// be parsed to a numeric score.
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    #[serde(rename = "package", default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<Vulnerability>,
}

/// OSV.dev API client with in-memory cache, proxy bypass, and fail-closed.
pub struct OsvClient {
    client: reqwest::Client,
    cache: RwLock<HashMap<String, (Instant, Vec<Vulnerability>)>>,
    ttl: Duration,
}

impl OsvClient {
    /// Create a new client with the given cache TTL.
    ///
    /// Security:
    /// - Bypasses `HTTP_PROXY` / `HTTPS_PROXY` via `no_proxy()` to avoid
    ///   circular routing through the CONNECT proxy that embeds this engine.
    /// - Uses rustls built-in Mozilla/webpki root CAs for TLS verification.
    ///   The sandbox's ephemeral MITM CA is NOT in this store, so bypassing
    ///   the proxy means we get genuine TLS verification against api.osv.dev.
    pub fn new(ttl: Duration) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // Bypass all proxy env vars — OSV queries must go direct.
            // This also means the sandbox MITM CA is irrelevant; rustls
            // verifies against its compiled-in Mozilla root store.
            .no_proxy()
            .build()
            .expect("failed to build OSV HTTP client");

        Self {
            client,
            cache: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Query OSV.dev for vulnerabilities affecting a specific package version.
    ///
    /// Results are cached by `{ecosystem}/{package}/{version}` with the configured TTL.
    ///
    /// Returns `Err` when the OSV API is unreachable or returns an invalid
    /// response.  Callers should use the enforcement mode to decide whether
    /// to deny (enforce) or allow-with-warning (audit) the package.
    pub async fn query(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Result<Vec<Vulnerability>, OsvQueryError> {
        let cache_key = format!("{ecosystem}/{package}/{version}");

        // Check cache first. Keep the lock only for map access so outbound OSV
        // requests do not serialize unrelated tunnel traffic.
        {
            let cache = self.cache.read().expect("OSV cache read lock poisoned");
            if let Some((cached_at, vulns)) = cache.get(&cache_key) {
                if cached_at.elapsed() < self.ttl {
                    debug!(cache_key = %cache_key, count = vulns.len(), "OSV cache hit");
                    return Ok(vulns.clone());
                }
            }
        }

        // Best-effort eager eviction for expired entries.
        {
            let mut cache = self.cache.write().expect("OSV cache write lock poisoned");
            if cache
                .get(&cache_key)
                .is_some_and(|(cached_at, _)| cached_at.elapsed() >= self.ttl)
            {
                cache.remove(&cache_key);
            }
        }

        // Query OSV API.
        let body = serde_json::json!({
            "package": {
                "name": package,
                "ecosystem": ecosystem,
            },
            "version": version,
        });

        let resp = self
            .client
            .post(OSV_API_URL)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                warn!(cache_key = %cache_key, error = %e, "OSV query failed");
                OsvQueryError::Network(e.to_string())
            })?;

        const MAX_RESPONSE_BYTES: usize = 2_097_152; // 2 MiB

        let bytes = resp.bytes().await.map_err(|e| {
            warn!(cache_key = %cache_key, error = %e, "Failed to read OSV response body");
            OsvQueryError::Network(e.to_string())
        })?;

        if bytes.len() > MAX_RESPONSE_BYTES {
            warn!(cache_key = %cache_key, size = bytes.len(), "OSV response too large");
            return Err(OsvQueryError::ResponseTooLarge(bytes.len()));
        }

        let parsed: OsvResponse = serde_json::from_slice(&bytes).map_err(|e| {
            warn!(cache_key = %cache_key, error = %e, "Failed to parse OSV response");
            OsvQueryError::ParseError(e.to_string())
        })?;

        info!(
            cache_key = %cache_key,
            count = parsed.vulns.len(),
            "OSV query successful"
        );

        let vulns = parsed.vulns;
        self.cache
            .write()
            .expect("OSV cache write lock poisoned")
            .insert(cache_key, (Instant::now(), vulns.clone()));
        Ok(vulns)
    }

    /// Classify vulnerabilities into severity buckets.
    pub fn count_by_severity(vulns: &[Vulnerability]) -> (u32, u32, u32, u32) {
        let mut critical = 0u32;
        let mut high = 0u32;
        let mut medium = 0u32;
        let mut low = 0u32;

        for vuln in vulns {
            let severity = classify_severity(vuln);
            match severity.as_str() {
                "CRITICAL" => critical += 1,
                "HIGH" => high += 1,
                "MEDIUM" => medium += 1,
                _ => low += 1,
            }
        }

        (critical, high, medium, low)
    }

    #[cfg(test)]
    pub(crate) fn seed_cache(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        vulns: Vec<Vulnerability>,
    ) {
        let cache_key = format!("{ecosystem}/{package}/{version}");
        self.cache
            .write()
            .expect("OSV cache write lock poisoned")
            .insert(cache_key, (Instant::now(), vulns));
    }
}

/// Extract the first fixed version from a vulnerability's affected ranges.
pub fn extract_fixed_version(vuln: &Vulnerability) -> Option<String> {
    for affected in &vuln.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(ref fixed) = event.fixed {
                    return Some(fixed.clone());
                }
            }
        }
    }
    None
}

/// Classify a vulnerability severity from its CVSS score or metadata.
pub fn classify_severity(vuln: &Vulnerability) -> String {
    // Try numeric CVSS score first, then CVSS vector string.
    for sev in &vuln.severity {
        if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
            // Plain numeric score (e.g., "9.8")
            if let Ok(score) = sev.score.parse::<f32>() {
                return cvss_score_to_label(score);
            }
            // CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")
            if let Some(score) = parse_cvss_base_score(&sev.score) {
                return cvss_score_to_label(score);
            }
        }
    }
    // Fallback: use database_specific.severity (e.g., "CRITICAL", "HIGH",
    // "MODERATE"). GitHub Advisory Database always provides this.
    if let Some(ref db) = vuln.database_specific {
        if let Some(ref label) = db.severity {
            return match label.to_ascii_uppercase().as_str() {
                "CRITICAL" => "CRITICAL",
                "HIGH" => "HIGH",
                "MODERATE" | "MEDIUM" => "MEDIUM",
                "LOW" => "LOW",
                _ => "MEDIUM",
            }
            .to_string();
        }
    }
    "MEDIUM".to_string()
}

fn cvss_score_to_label(score: f32) -> String {
    match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        _ => "LOW",
    }
    .to_string()
}

/// Extract the base score from a CVSS v3 vector string.
///
/// Computes an approximate CVSS 3.x base score from the vector components.
/// Uses the simplified scoring approach: maps each metric to its weight and
/// computes the exploitability and impact sub-scores.
fn parse_cvss_base_score(vector: &str) -> Option<f32> {
    if !vector.starts_with("CVSS:3") {
        return None;
    }
    let mut av = 0.85_f32; // Network
    let mut ac = 0.77; // Low
    let mut pr = 0.85; // None
    let mut ui = 0.85; // None
    let mut scope_changed = false;
    let mut conf = 0.0_f32;
    let mut integ = 0.0_f32;
    let mut avail = 0.0_f32;

    for part in vector.split('/') {
        match part {
            "AV:N" => av = 0.85,
            "AV:A" => av = 0.62,
            "AV:L" => av = 0.55,
            "AV:P" => av = 0.20,
            "AC:L" => ac = 0.77,
            "AC:H" => ac = 0.44,
            "PR:N" => pr = 0.85,
            "PR:L" => pr = if scope_changed { 0.68 } else { 0.62 },
            "PR:H" => pr = if scope_changed { 0.50 } else { 0.27 },
            "UI:N" => ui = 0.85,
            "UI:R" => ui = 0.62,
            "S:U" => scope_changed = false,
            "S:C" => scope_changed = true,
            "C:H" => conf = 0.56,
            "C:L" => conf = 0.22,
            "C:N" => conf = 0.0,
            "I:H" => integ = 0.56,
            "I:L" => integ = 0.22,
            "I:N" => integ = 0.0,
            "A:H" => avail = 0.56,
            "A:L" => avail = 0.22,
            "A:N" => avail = 0.0,
            _ => {}
        }
    }
    // Re-evaluate PR after scope is known
    for part in vector.split('/') {
        match part {
            "PR:L" => pr = if scope_changed { 0.68 } else { 0.62 },
            "PR:H" => pr = if scope_changed { 0.50 } else { 0.27 },
            _ => {}
        }
    }

    let iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let score = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // Round up to one decimal
    Some((score * 10.0).ceil() / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn query_returns_seeded_cache_entry() {
        let client = OsvClient::new(Duration::from_secs(60));
        let cached = vec![Vulnerability {
            id: "OSV-1".into(),
            summary: "cached".into(),
            severity: vec![],
            affected: vec![],
            database_specific: None,
        }];
        client.seed_cache("npm", "left-pad", "1.0.0", cached.clone());

        let result = client.query("npm", "left-pad", "1.0.0").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, cached[0].id);
    }

    #[test]
    fn classify_critical() {
        let vuln = Vulnerability {
            id: "CVE-2024-0001".to_string(),
            summary: "test".to_string(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "9.8".to_string(),
            }],
            affected: vec![],
            database_specific: None,
        };
        assert_eq!(classify_severity(&vuln), "CRITICAL");
    }

    #[test]
    fn classify_high() {
        let vuln = Vulnerability {
            id: "CVE-2024-0002".to_string(),
            summary: "test".to_string(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "7.5".to_string(),
            }],
            affected: vec![],
            database_specific: None,
        };
        assert_eq!(classify_severity(&vuln), "HIGH");
    }

    #[test]
    fn count_severity_buckets() {
        let vulns = vec![
            Vulnerability {
                id: "A".into(),
                summary: String::new(),
                severity: vec![OsvSeverity {
                    severity_type: "CVSS_V3".into(),
                    score: "9.8".into(),
                }],
                affected: vec![],
                database_specific: None,
            },
            Vulnerability {
                id: "B".into(),
                summary: String::new(),
                severity: vec![OsvSeverity {
                    severity_type: "CVSS_V3".into(),
                    score: "7.0".into(),
                }],
                affected: vec![],
                database_specific: None,
            },
            Vulnerability {
                id: "C".into(),
                summary: String::new(),
                severity: vec![],
                affected: vec![],
                database_specific: None,
            },
        ];
        let (c, h, m, l) = OsvClient::count_by_severity(&vulns);
        assert_eq!(c, 1);
        assert_eq!(h, 1);
        assert_eq!(m, 1); // No CVSS defaults to medium
        assert_eq!(l, 0);
    }
}
