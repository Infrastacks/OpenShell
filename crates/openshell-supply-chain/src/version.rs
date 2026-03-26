// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Semver version pinning enforcement.

use crate::policy::VersionPin;
use tracing::warn;

/// Check if a package version satisfies its version pin.
///
/// Returns `Some(reason)` if the version violates the pin, `None` if it passes.
pub fn check_version_pin(
    ecosystem: &str,
    package: &str,
    version: &str,
    pins: &[VersionPin],
) -> Option<String> {
    for pin in pins {
        if pin.ecosystem.to_ascii_lowercase() != ecosystem.to_ascii_lowercase() {
            continue;
        }
        if pin.package != package {
            continue;
        }
        // Parse the installed version and the requirement.
        let installed = match semver::Version::parse(version) {
            Ok(v) => v,
            Err(_) => {
                warn!(
                    package = package,
                    version = version,
                    "Cannot parse version as semver, skipping pin check"
                );
                return None;
            }
        };
        let req = match semver::VersionReq::parse(&pin.range) {
            Ok(r) => r,
            Err(_) => {
                warn!(
                    package = package,
                    range = %pin.range,
                    "Cannot parse version pin range, skipping"
                );
                return None;
            }
        };
        if !req.matches(&installed) {
            return Some(format!(
                "version {version} does not satisfy pin {range} for {package}",
                range = pin.range,
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(pkg: &str, eco: &str, range: &str) -> VersionPin {
        VersionPin {
            package: pkg.to_string(),
            ecosystem: eco.to_string(),
            range: range.to_string(),
        }
    }

    #[test]
    fn satisfies_pin() {
        let pins = vec![pin("lodash", "npm", ">=4.17.21")];
        assert!(check_version_pin("npm", "lodash", "4.17.21", &pins).is_none());
        assert!(check_version_pin("npm", "lodash", "4.18.0", &pins).is_none());
    }

    #[test]
    fn violates_pin() {
        let pins = vec![pin("lodash", "npm", ">=4.17.21")];
        let result = check_version_pin("npm", "lodash", "4.17.20", &pins);
        assert!(result.is_some());
        assert!(result.unwrap().contains("does not satisfy"));
    }

    #[test]
    fn different_ecosystem_skipped() {
        let pins = vec![pin("requests", "pypi", ">=2.31.0")];
        assert!(check_version_pin("npm", "requests", "1.0.0", &pins).is_none());
    }

    #[test]
    fn no_pins_passes() {
        assert!(check_version_pin("npm", "lodash", "1.0.0", &[]).is_none());
    }
}
