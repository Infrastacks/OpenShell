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
    cache: HashMap<String, (Instant, Vec<Vulnerability>)>,
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
            cache: HashMap::new(),
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
        &mut self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Result<Vec<Vulnerability>, OsvQueryError> {
        let cache_key = format!("{ecosystem}/{package}/{version}");

        // Check cache — evict expired entries eagerly to bound memory growth.
        let expired = self
            .cache
            .get(&cache_key)
            .map(|(cached_at, _)| cached_at.elapsed() >= self.ttl);
        match expired {
            Some(false) => {
                let vulns = &self.cache[&cache_key].1;
                debug!(cache_key = %cache_key, count = vulns.len(), "OSV cache hit");
                return Ok(vulns.clone());
            }
            Some(true) => {
                self.cache.remove(&cache_key);
            }
            None => {}
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
        self.cache.insert(cache_key, (Instant::now(), vulns.clone()));
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
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                _ => low += 1,
            }
        }

        (critical, high, medium, low)
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
    for sev in &vuln.severity {
        if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
            if let Ok(score) = sev.score.parse::<f32>() {
                return match score {
                    s if s >= 9.0 => "critical",
                    s if s >= 7.0 => "high",
                    s if s >= 4.0 => "medium",
                    _ => "low",
                }
                .to_string();
            }
        }
    }
    // Default to medium if no CVSS score available.
    "medium".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        assert_eq!(classify_severity(&vuln), "critical");
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
        };
        assert_eq!(classify_severity(&vuln), "high");
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
            },
            Vulnerability {
                id: "B".into(),
                summary: String::new(),
                severity: vec![OsvSeverity {
                    severity_type: "CVSS_V3".into(),
                    score: "7.0".into(),
                }],
                affected: vec![],
            },
            Vulnerability {
                id: "C".into(),
                summary: String::new(),
                severity: vec![],
                affected: vec![],
            },
        ];
        let (c, h, m, l) = OsvClient::count_by_severity(&vulns);
        assert_eq!(c, 1);
        assert_eq!(h, 1);
        assert_eq!(m, 1); // No CVSS defaults to medium
        assert_eq!(l, 0);
    }
}
