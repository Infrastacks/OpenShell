// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OSV.dev API client with in-memory TTL cache, certificate pinning, and
//! fail-closed behaviour.
//!
//! Security hardening:
//! - **Proxy bypass**: the HTTP client is built with `no_proxy("*")` so OSV
//!   queries go direct, avoiding circular routing through the CONNECT proxy
//!   that embeds this engine.
//! - **CA pinning**: only the Google Trust Services root CA (GTS Root R1) is
//!   trusted — system and MITM CAs are excluded.  DNS hijack → TLS failure.
//! - **Fail-closed**: `query()` returns `Result`.  In `enforce` mode callers
//!   must deny the package when OSV is unreachable.
//! - **Response validation**: oversized or unparseable responses are rejected.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

/// Google Trust Services Root R1 (PEM).
/// Issuer of GTS CA 1C3 which signs api.osv.dev.
/// Valid until 2036-06-22.  SHA-256 fingerprint:
/// D9:47:43:2A:BD:E7:B7:FA:90:FC:2E:6B:59:10:1B:12:80:E0:E1:C7:E4:E4:0F:A3:C6:88:7F:FF:57:A7:F4:CF
const GTS_ROOT_R1_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7
wCl7raKb0xlpHDU0QM+NOsROjjBsvJcF4rFHN+o7DAEaOJV1nioTnPOcVzqxjoCM
5l0IMts/1aNqJclYb1GjQ1WBfSzfC0KsfLREKB/dqJED3C3GFEGjlBqm1HbME2OO
KlwJMJsyrStDmmPQLbY3KYf+2MsDBRdSFqG6K/4F/amiLCaFahKLLJwS93C+NSWI
Cl+cz2kDwSB8rsLKRFywkSNEEn1ByMYOASTPWv+PsIGGK5ipWS/FHHI79hdFkc8H
HbCFFOdNaP6Z+1Rl3sDi5230YCiCDxRIiQ3naBbWNhSgFr0JHNvKxJVapJhSg3Sg
o+k+hEhUMQQZ9JkqnGGgN/HI7GxCUvPVNELnJzksEwlJwGDbR4TKcgJNWWOaSOA
KF2HRLY2L1gOI7C0FMztYrBMfANFtlhPCTILJcGFJIqv8h0B3qSMP4HTPKMBNmKm
cmXvJ5s2zg/GGqE5xyLBE2MQzanGQSLfNBigUbsKl0GUIPQWlz0aIl0cVlB+gtvO
p/0M6w/KiN1RkKkM7mDvLflYH3jcMQA/j5cVISi3gSJHOGOkBJjVLQIDAQABo0Iw
QDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU5K8r
JnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQELBQADggIBAJ+qQibbC5u+/x65
03MTN7S9FqBZiGFjkWenFcNGLPJYLTqDqq/8NIpBRi3a3r/rYkliArwhmcEI85zK
iLxVNoj39GhiV7K3WPpIeJHaQppnAiMhBCMiFm8P9F1FRZ8m9Wil1GTJDif7Aylz
TH8mvOmRnfAFQ2FnVNxYLOR3VIkaPMW7sqajRNMiidcFi1pCGkGylhbrFICH3hQP
q+sUaBQ+KtMPbo+E+Bki0gJFwXqBWjfR9bIWTdINB2LSQMKBP4BCI/Kpf/GNHCM
UVmHdIFqyMqvvIEB5X3PBF/boyiDOjkJODzS9BnCDMGEYB0ME2ICMvISOFFa6J2L
GHNpKWgTPkBNBaJ3EDiKFDEhAQEAfm/B2mC2IIcEOPHmE6PrFuOFhRs/bP/4Gs7Z
baF23rhXCAMU7JsJw/LA3gjksVfODtU1eHHQHbKJILbBei+5aYJJj2La0s7OvtJe
l4k22i7mUgMBqTXPJ8A0z5OdYKDn99Dq5cP0Q4LgFmGIT6O9M5TBjh1JC0S+iMKq
ql+YJTp2M5fQQItkvFDA0bHp0bwrB+eCRh3OgSlV+mYee5RJ7B4JjISGRK6D+AGjS
VmvSzJQCByJtR1Q99VK2mZnACSIPHECDOJAPEoJMH3jJN0EKPL7ZPJIFvnMJIBBn
WcBN1c+aFKUXYcjMjYJaR97UBg3l
-----END CERTIFICATE-----";

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

/// OSV.dev API client with in-memory cache, CA pinning, and proxy bypass.
pub struct OsvClient {
    client: reqwest::Client,
    cache: HashMap<String, (Instant, Vec<Vulnerability>)>,
    ttl: Duration,
}

impl OsvClient {
    /// Create a new client with the given cache TTL.
    ///
    /// The client is hardened against DNS hijack and proxy interference:
    /// - Bypasses `HTTP_PROXY` / `HTTPS_PROXY` (avoids routing through the
    ///   CONNECT proxy that embeds this engine).
    /// - Pins Google Trust Services Root R1 as the only trusted CA.
    pub fn new(ttl: Duration) -> Self {
        let gts_root = reqwest::Certificate::from_pem(GTS_ROOT_R1_PEM)
            .expect("GTS Root R1 PEM is invalid");

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // Bypass all proxy env vars — OSV queries must go direct.
            .no_proxy()
            // Pin to Google Trust Services root CA only.
            // System CAs and any MITM CAs from the sandbox proxy are excluded.
            .tls_built_in_root_certs(false)
            .add_root_certificate(gts_root)
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
