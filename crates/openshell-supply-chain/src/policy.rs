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

/// Result of evaluating a package against supply chain policy.
#[derive(Debug)]
pub struct SupplyChainResult {
    pub decision: Decision,
    pub denial_reason: Option<String>,
    pub vuln_counts: VulnCounts,
    pub license_status: LicenseStatus,
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
    pub async fn evaluate(&mut self, registry_match: &RegistryMatch) -> SupplyChainResult {
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
                };
            }
        }

        // 3. License check (placeholder — real check needs package metadata API)
        let license_status = LicenseStatus::Unknown;

        // 4. OSV vulnerability lookup
        let vuln_counts = if !version_str.is_empty() {
            let vulns = self.osv.query(&ecosystem, package, version_str).await;
            let (c, h, m, l) = OsvClient::count_by_severity(&vulns);
            VulnCounts {
                critical: c,
                high: h,
                medium: m,
                low: l,
            }
        } else {
            VulnCounts::default()
        };

        // 5. Threshold evaluation
        let thresholds = &self.policy.vulnerability_thresholds;
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
            };
        }

        SupplyChainResult {
            decision: Decision::Allow,
            denial_reason: None,
            vuln_counts,
            license_status,
        }
    }
}
