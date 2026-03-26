// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OSV.dev API client with in-memory TTL cache.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

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

/// OSV.dev API client with in-memory cache.
pub struct OsvClient {
    client: reqwest::Client,
    cache: HashMap<String, (Instant, Vec<Vulnerability>)>,
    ttl: Duration,
}

impl OsvClient {
    /// Create a new client with the given cache TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build reqwest client"),
            cache: HashMap::new(),
            ttl,
        }
    }

    /// Query OSV.dev for vulnerabilities affecting a specific package version.
    ///
    /// Results are cached by `{ecosystem}/{package}/{version}` with the configured TTL.
    /// Network errors are treated as non-blocking: returns empty vec with a warning log.
    pub async fn query(
        &mut self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Vec<Vulnerability> {
        let cache_key = format!("{ecosystem}/{package}/{version}");

        // Check cache.
        if let Some((cached_at, vulns)) = self.cache.get(&cache_key) {
            if cached_at.elapsed() < self.ttl {
                debug!(cache_key = %cache_key, count = vulns.len(), "OSV cache hit");
                return vulns.clone();
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

        let result = self
            .client
            .post(OSV_API_URL)
            .json(&body)
            .send()
            .await;

        const MAX_RESPONSE_BYTES: usize = 2_097_152; // 2 MiB

        let vulns = match result {
            Ok(resp) => {
                let bytes = match resp.bytes().await {
                    Ok(b) if b.len() <= MAX_RESPONSE_BYTES => b,
                    Ok(b) => {
                        warn!(cache_key = %cache_key, size = b.len(), "OSV response too large, discarding");
                        self.cache.insert(cache_key, (Instant::now(), Vec::new()));
                        return Vec::new();
                    }
                    Err(e) => {
                        warn!(cache_key = %cache_key, error = %e, "Failed to read OSV response body");
                        return Vec::new();
                    }
                };
                match serde_json::from_slice::<OsvResponse>(&bytes) {
                    Ok(parsed) => {
                        debug!(
                            cache_key = %cache_key,
                            count = parsed.vulns.len(),
                            "OSV query successful"
                        );
                        parsed.vulns
                    }
                    Err(e) => {
                        warn!(cache_key = %cache_key, error = %e, "Failed to parse OSV response");
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                warn!(
                    cache_key = %cache_key,
                    error = %e,
                    "OSV query failed, allowing package (fail-open)"
                );
                Vec::new()
            }
        };

        self.cache.insert(cache_key, (Instant::now(), vulns.clone()));
        vulns
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
