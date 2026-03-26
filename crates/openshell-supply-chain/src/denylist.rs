// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Package denylist with exact and glob matching.

use crate::policy::DenylistEntry;

/// Check if a package is on the denylist.
///
/// Returns the denial reason if matched, `None` if allowed.
pub fn check_denylist(
    ecosystem: &str,
    package: &str,
    denylist: &[DenylistEntry],
) -> Option<String> {
    for entry in denylist {
        if !entry.ecosystem.is_empty()
            && entry.ecosystem.to_ascii_lowercase() != ecosystem.to_ascii_lowercase()
        {
            continue;
        }
        if glob_match(&entry.package, package) {
            return Some(entry.reason.clone());
        }
    }
    None
}

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

    fn entry(pkg: &str, eco: &str, reason: &str) -> DenylistEntry {
        DenylistEntry {
            package: pkg.to_string(),
            ecosystem: eco.to_string(),
            reason: reason.to_string(),
        }
    }

    #[test]
    fn exact_match() {
        let denylist = vec![entry("event-stream", "npm", "supply chain attack")];
        let result = check_denylist("npm", "event-stream", &denylist);
        assert_eq!(result.unwrap(), "supply chain attack");
    }

    #[test]
    fn ecosystem_mismatch() {
        let denylist = vec![entry("event-stream", "npm", "attack")];
        assert!(check_denylist("pypi", "event-stream", &denylist).is_none());
    }

    #[test]
    fn glob_match_works() {
        let denylist = vec![entry("malicious-*", "npm", "malicious family")];
        assert!(check_denylist("npm", "malicious-package", &denylist).is_some());
        assert!(check_denylist("npm", "safe-package", &denylist).is_none());
    }

    #[test]
    fn empty_denylist() {
        assert!(check_denylist("npm", "anything", &[]).is_none());
    }
}
