// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPDX license allow/deny checking with glob support.

use serde::{Deserialize, Serialize};

/// License check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Allowed,
    Denied,
    Unknown,
}

/// Check a license identifier against allow/deny lists.
///
/// Evaluation order:
/// 1. If explicitly denied → `Denied`
/// 2. If explicitly allowed → `Allowed`
/// 3. If allow list is non-empty and not matched → `Denied` (allowlist is restrictive)
/// 4. If allow list is empty → `Unknown`
pub fn check_license(license: &str, allowed: &[String], denied: &[String]) -> LicenseStatus {
    // Check deny list first.
    for pattern in denied {
        if glob_match(pattern, license) {
            return LicenseStatus::Denied;
        }
    }

    // Check allow list.
    if !allowed.is_empty() {
        for pattern in allowed {
            if glob_match(pattern, license) {
                return LicenseStatus::Allowed;
            }
        }
        // Allowlist is non-empty but didn't match — deny by default.
        return LicenseStatus::Denied;
    }

    LicenseStatus::Unknown
}

/// Simple glob matching: only supports trailing `*` (e.g., `BSD-*`).
fn glob_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_exact() {
        let allowed = vec!["MIT".to_string(), "Apache-2.0".to_string()];
        assert_eq!(check_license("MIT", &allowed, &[]), LicenseStatus::Allowed);
    }

    #[test]
    fn allowed_glob() {
        let allowed = vec!["BSD-*".to_string()];
        assert_eq!(
            check_license("BSD-2-Clause", &allowed, &[]),
            LicenseStatus::Allowed
        );
        assert_eq!(
            check_license("BSD-3-Clause", &allowed, &[]),
            LicenseStatus::Allowed
        );
    }

    #[test]
    fn denied_exact() {
        let denied = vec!["GPL-3.0".to_string()];
        let allowed = vec!["MIT".to_string()];
        assert_eq!(
            check_license("GPL-3.0", &allowed, &denied),
            LicenseStatus::Denied
        );
    }

    #[test]
    fn denied_glob() {
        let denied = vec!["AGPL-*".to_string()];
        assert_eq!(
            check_license("AGPL-3.0-only", &[], &denied),
            LicenseStatus::Denied
        );
    }

    #[test]
    fn deny_overrides_allow() {
        let allowed = vec!["GPL-*".to_string()];
        let denied = vec!["GPL-3.0".to_string()];
        assert_eq!(
            check_license("GPL-3.0", &allowed, &denied),
            LicenseStatus::Denied
        );
    }

    #[test]
    fn not_in_allowlist_denied() {
        let allowed = vec!["MIT".to_string()];
        assert_eq!(check_license("ISC", &allowed, &[]), LicenseStatus::Denied);
    }

    #[test]
    fn empty_lists_unknown() {
        assert_eq!(check_license("MIT", &[], &[]), LicenseStatus::Unknown);
    }
}
