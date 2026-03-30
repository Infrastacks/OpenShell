// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supply chain policy configuration and evaluation engine.

use crate::denylist;
use crate::license::LicenseStatus;
use crate::osv_client::OsvClient;
use crate::registry::RegistryMatch;
use crate::version;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use tracing::info;

/// Supply chain policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainPolicy {
    pub enforcement: String,
    #[serde(default)]
    pub vulnerability_thresholds: VulnThresholds,
    #[serde(default)]
    pub license_policy: LicensePolicy,
    #[serde(default)]
    pub denylist: Vec<DenylistEntry>,
    #[serde(default)]
    pub version_pinning: Vec<VersionPin>,
    #[serde(default = "default_osv_ttl_hours")]
    pub osv_cache_ttl_hours: u64,
}

fn default_osv_ttl_hours() -> u64 {
    4
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnThresholds {
    #[serde(default)]
    pub max_critical: u32,
    #[serde(default = "default_max_high")]
    pub max_high: u32,
    #[serde(default)]
    pub block_unfixed_critical: bool,
}

fn default_max_high() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicensePolicy {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub denied: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenylistEntry {
    pub package: String,
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionPin {
    pub package: String,
    pub ecosystem: String,
    pub range: String,
}

/// Evaluation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Audit,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::Audit => write!(f, "audit"),
        }
    }
}

/// Vulnerability counts by severity.
#[derive(Debug, Clone, Default)]
pub struct VulnCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

/// Summary of a single vulnerability for telemetry emission.
#[derive(Debug, Clone)]
pub struct VulnDetail {
    pub osv_id: String,
    pub severity: String,
    pub summary: String,
    pub fixed_version: Option<String>,
}

/// Result of evaluating a package against supply chain policy.
#[derive(Debug)]
pub struct SupplyChainResult {
    pub decision: Decision,
    pub denial_reason: Option<String>,
    pub vuln_counts: VulnCounts,
    pub license_status: LicenseStatus,
    /// Individual vulnerabilities found (for telemetry events).
    pub vulnerabilities: Vec<VulnDetail>,
}

/// Supply chain evaluation engine.
pub struct SupplyChainEngine {
    policy: SupplyChainPolicy,
    osv: OsvClient,
}

impl SupplyChainEngine {
    pub fn new(policy: &SupplyChainPolicy) -> Self {
        let ttl = Duration::from_secs(policy.osv_cache_ttl_hours * 3600);
        Self {
            policy: policy.clone(),
            osv: OsvClient::new(ttl),
        }
    }

    /// Evaluate a detected package install against the policy.
    ///
    /// Evaluation order:
    /// 1. Denylist (instant deny)
    /// 2. Version pinning
    /// 3. License check (requires package metadata — skipped if unknown)
    /// 4. OSV vulnerability lookup
    /// 5. Threshold evaluation
    pub async fn evaluate(&self, registry_match: &RegistryMatch) -> SupplyChainResult {
        let ecosystem = registry_match.ecosystem.to_string();
        let package = &registry_match.package;
        let version_str = &registry_match.version;
        let enforce = self.policy.enforcement == "enforce";

        // 1. Denylist
        if let Some(reason) = denylist::check_denylist(&ecosystem, package, &self.policy.denylist) {
            info!(
                engine = "supply_chain",
                check = "denylist",
                ecosystem = %ecosystem,
                package = %package,
                reason = %reason,
                "Package is on denylist"
            );
            return SupplyChainResult {
                decision: if enforce { Decision::Deny } else { Decision::Audit },
                denial_reason: Some(format!("denylisted: {reason}")),
                vuln_counts: VulnCounts::default(),
                license_status: LicenseStatus::Unknown,
                vulnerabilities: Vec::new(),
            };
        }

        // 2. Version pinning
        if !version_str.is_empty() {
            if let Some(reason) =
                version::check_version_pin(&ecosystem, package, version_str, &self.policy.version_pinning)
            {
                info!(
                    engine = "supply_chain",
                    check = "version_pin",
                    ecosystem = %ecosystem,
                    package = %package,
                    version = %version_str,
                    reason = %reason,
                    "Version pin violated"
                );
                return SupplyChainResult {
                    decision: if enforce { Decision::Deny } else { Decision::Audit },
                    denial_reason: Some(reason),
                    vuln_counts: VulnCounts::default(),
                    license_status: LicenseStatus::Unknown,
                    vulnerabilities: Vec::new(),
                };
            }
        }

        // 3. License check (placeholder — real check needs package metadata API)
        let license_status = LicenseStatus::Unknown;

        // 4. OSV vulnerability lookup (fail-closed in enforce mode)
        let (vuln_counts, vuln_details) = if !version_str.is_empty() {
            match self.osv.query(&ecosystem, package, version_str).await {
                Ok(vulns) => {
                    let (c, h, m, l) = OsvClient::count_by_severity(&vulns);
                    let details: Vec<VulnDetail> = vulns
                        .iter()
                        .map(|v| VulnDetail {
                            osv_id: v.id.clone(),
                            severity: crate::osv_client::classify_severity(v),
                            summary: v.summary.clone(),
                            fixed_version: crate::osv_client::extract_fixed_version(v),
                        })
                        .collect();
                    (VulnCounts { critical: c, high: h, medium: m, low: l }, details)
                }
                Err(e) => {
                    // Fail-closed: if OSV is unreachable in enforce mode, deny.
                    // In audit mode, allow with warning.
                    if enforce {
                        let reason = format!(
                            "vulnerability database unreachable ({e}); \
                             denying install per fail-closed policy"
                        );
                        return SupplyChainResult {
                            decision: Decision::Deny,
                            denial_reason: Some(reason),
                            vuln_counts: VulnCounts::default(),
                            license_status,
                            vulnerabilities: Vec::new(),
                        };
                    }
                    info!(
                        engine = "supply_chain",
                        error = %e,
                        ecosystem = %ecosystem,
                        package = %package,
                        "OSV unreachable, allowing in audit mode"
                    );
                    (VulnCounts::default(), Vec::new())
                }
            }
        } else {
            (VulnCounts::default(), Vec::new())
        };

        // 5. Block unfixed critical vulnerabilities
        let thresholds = &self.policy.vulnerability_thresholds;
        if thresholds.block_unfixed_critical {
            let unfixed_critical = vuln_details
                .iter()
                .any(|v| v.severity == "CRITICAL" && v.fixed_version.is_none());
            if unfixed_critical {
                let reason = "unfixed critical vulnerability detected".to_string();
                info!(
                    engine = "supply_chain",
                    check = "block_unfixed_critical",
                    ecosystem = %ecosystem,
                    package = %package,
                    "Unfixed critical vulnerability"
                );
                return SupplyChainResult {
                    decision: if enforce { Decision::Deny } else { Decision::Audit },
                    denial_reason: Some(reason),
                    vuln_counts,
                    license_status,
                    vulnerabilities: vuln_details,
                };
            }
        }

        // 6. Threshold evaluation
        if vuln_counts.critical > thresholds.max_critical {
            let reason = format!(
                "{} critical vulnerabilities (max: {})",
                vuln_counts.critical, thresholds.max_critical
            );
            return SupplyChainResult {
                decision: if enforce { Decision::Deny } else { Decision::Audit },
                denial_reason: Some(reason),
                vuln_counts,
                license_status,
                vulnerabilities: vuln_details,
            };
        }
        if vuln_counts.high > thresholds.max_high {
            let reason = format!(
                "{} high vulnerabilities (max: {})",
                vuln_counts.high, thresholds.max_high
            );
            return SupplyChainResult {
                decision: if enforce { Decision::Deny } else { Decision::Audit },
                denial_reason: Some(reason),
                vuln_counts,
                license_status,
                vulnerabilities: vuln_details,
            };
        }

        SupplyChainResult {
            decision: Decision::Allow,
            denial_reason: None,
            vuln_counts,
            license_status,
            vulnerabilities: vuln_details,
        }
    }

    #[cfg(test)]
    pub(crate) fn seed_osv_cache(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        vulns: Vec<crate::osv_client::Vulnerability>,
    ) {
        self.osv.seed_cache(ecosystem, package, version, vulns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Ecosystem;
    use crate::Vulnerability;

    #[tokio::test]
    async fn evaluate_uses_seeded_osv_cache() {
        let policy = SupplyChainPolicy {
            enforcement: "enforce".to_string(),
            vulnerability_thresholds: VulnThresholds {
                max_critical: 0,
                max_high: 5,
                block_unfixed_critical: false,
            },
            license_policy: LicensePolicy::default(),
            denylist: Vec::new(),
            version_pinning: Vec::new(),
            osv_cache_ttl_hours: 1,
        };
        let engine = SupplyChainEngine::new(&policy);
        engine.seed_osv_cache(
            "npm",
            "left-pad",
            "1.0.0",
            vec![Vulnerability {
                id: "OSV-2026-1".into(),
                summary: "critical".into(),
                severity: vec![crate::osv_client::OsvSeverity {
                    severity_type: "CVSS_V3".into(),
                    score: "9.8".into(),
                }],
                affected: vec![],
                database_specific: None,
            }],
        );

        let result = engine
            .evaluate(&RegistryMatch {
                ecosystem: Ecosystem::Npm,
                package: "left-pad".into(),
                version: "1.0.0".into(),
            })
            .await;

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.vuln_counts.critical, 1);
        assert_eq!(result.vulnerabilities.len(), 1);
    }

    #[test]
    fn serde_round_trip() {
        let yaml = r#"
enforcement: enforce
vulnerability_thresholds:
  max_critical: 0
  max_high: 3
  block_unfixed_critical: true
license_policy:
  allowed: [MIT, Apache-2.0]
  denied: [GPL-3.0]
denylist:
  - package: left-pad
    ecosystem: npm
    reason: "npm incident"
version_pinning:
  - package: lodash
    ecosystem: npm
    range: ">=4.0.0,<5.0.0"
osv_cache_ttl_hours: 8
"#;
        let policy: SupplyChainPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.enforcement, "enforce");
        assert_eq!(policy.vulnerability_thresholds.max_critical, 0);
        assert_eq!(policy.vulnerability_thresholds.max_high, 3);
        assert!(policy.vulnerability_thresholds.block_unfixed_critical);
        assert_eq!(policy.license_policy.allowed, vec!["MIT", "Apache-2.0"]);
        assert_eq!(policy.license_policy.denied, vec!["GPL-3.0"]);
        assert_eq!(policy.denylist.len(), 1);
        assert_eq!(policy.denylist[0].package, "left-pad");
        assert_eq!(policy.version_pinning.len(), 1);
        assert_eq!(policy.osv_cache_ttl_hours, 8);

        let json = serde_json::to_string(&policy).unwrap();
        let restored: SupplyChainPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.enforcement, "enforce");
        assert!(restored.vulnerability_thresholds.block_unfixed_critical);
    }

    #[test]
    fn default_thresholds() {
        // derive(Default) uses u32::default() = 0 for all fields.
        // serde(default = "default_max_high") only applies during deserialization.
        let t = VulnThresholds::default();
        assert_eq!(t.max_critical, 0);
        assert_eq!(t.max_high, 0);
        assert!(!t.block_unfixed_critical);
    }

    #[test]
    fn serde_default_max_high() {
        // When deserialized with missing fields, serde uses default_max_high() = 5.
        let yaml = "max_critical: 0\n";
        let t: VulnThresholds = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(t.max_high, 5);
    }

    #[test]
    fn decision_display() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Deny.to_string(), "deny");
        assert_eq!(Decision::Audit.to_string(), "audit");
    }
}
