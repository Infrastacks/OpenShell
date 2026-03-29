// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Package registry pattern detection from HTTP host + path.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported package ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
    Go,
    Maven,
    NuGet,
}

impl fmt::Display for Ecosystem {
    /// Returns the OSV-compatible ecosystem identifier.
    ///
    /// These must match the official OSV ecosystem names exactly (case-sensitive)
    /// since the `Display` output is used in OSV API queries.
    /// See: <https://ossf.github.io/osv-schema/#affectedpackage-field>
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Npm => write!(f, "npm"),
            Self::PyPI => write!(f, "PyPI"),
            Self::Cargo => write!(f, "crates.io"),
            Self::Go => write!(f, "Go"),
            Self::Maven => write!(f, "Maven"),
            Self::NuGet => write!(f, "NuGet"),
        }
    }
}

/// A detected package registry request.
#[derive(Debug, Clone)]
pub struct RegistryMatch {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
}

/// Detect if an HTTP request targets a package registry.
///
/// Examines the host and URL path to classify the request as a package
/// install/download for a known ecosystem.
pub fn detect_registry_pattern(host: &str, path: &str) -> Option<RegistryMatch> {
    let host_lower = host.to_ascii_lowercase();

    // npm: registry.npmjs.org/<package>/-/<package>-<version>.tgz
    // npm: registry.npmjs.org/<@scope>/<package>/-/<package>-<version>.tgz
    if host_lower == "registry.npmjs.org" {
        return parse_npm(path);
    }

    // PyPI: files.pythonhosted.org/packages/.../<package>-<version>.tar.gz|.whl
    if host_lower == "files.pythonhosted.org" {
        return parse_pypi(path);
    }

    // Cargo: crates.io/api/v1/crates/<package>/<version>/download
    // Also: static.crates.io/crates/<package>/<package>-<version>.crate
    if host_lower == "crates.io" || host_lower == "static.crates.io" {
        return parse_cargo(path);
    }

    // Go: proxy.golang.org/<module>/@v/<version>.zip|.info|.mod
    if host_lower == "proxy.golang.org" {
        return parse_go(path);
    }

    // Maven: repo1.maven.org/maven2/<group-path>/<artifact>/<version>/...
    if host_lower == "repo1.maven.org" || host_lower.ends_with(".maven.org") {
        return parse_maven(path);
    }

    // NuGet: api.nuget.org/v3-flatcontainer/<package>/<version>/<package>.<version>.nupkg
    if host_lower == "api.nuget.org" {
        return parse_nuget(path);
    }

    None
}

fn parse_npm(path: &str) -> Option<RegistryMatch> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // Scoped: @scope/package/-/package-version.tgz  (4 parts minimum)
    // Unscoped: package/-/package-version.tgz  (3 parts minimum)
    if parts.len() >= 3 && parts.contains(&"-") {
        let dash_idx = parts.iter().position(|&p| p == "-")?;
        let package = if parts[0].starts_with('@') && dash_idx >= 2 {
            format!("{}/{}", parts[0], parts[1])
        } else {
            parts[0].to_string()
        };
        // Filename: package-version.tgz
        let filename = parts.last()?;
        let version = filename
            .strip_suffix(".tgz")?
            .rsplit_once('-')
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        if !version.is_empty() {
            return Some(RegistryMatch {
                ecosystem: Ecosystem::Npm,
                package,
                version,
            });
        }
    }
    // Metadata request: /<package> or /<@scope/package>
    if !parts.is_empty() && !parts[0].is_empty() {
        let package = if parts[0].starts_with('@') && parts.len() >= 2 {
            format!("{}/{}", parts[0], parts[1])
        } else {
            parts[0].to_string()
        };
        return Some(RegistryMatch {
            ecosystem: Ecosystem::Npm,
            package,
            version: String::new(),
        });
    }
    None
}

fn parse_pypi(path: &str) -> Option<RegistryMatch> {
    // files.pythonhosted.org/packages/<hash-prefix>/<hash>/<hash>/<filename>
    let filename = path.rsplit('/').next()?;
    // package-version.tar.gz, package-version-cpXX-*.whl, etc.
    let name_version = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".whl"))
        .or_else(|| filename.strip_suffix(".zip"))?;
    // Split on first '-' that's followed by a digit (version start).
    let mut split_idx = None;
    for (i, c) in name_version.char_indices() {
        if c == '-' {
            if let Some(next) = name_version.get(i + 1..i + 2) {
                if next.chars().next().is_some_and(|nc| nc.is_ascii_digit()) {
                    split_idx = Some(i);
                    break;
                }
            }
        }
    }
    let (package, version_part) = if let Some(idx) = split_idx {
        (&name_version[..idx], &name_version[idx + 1..])
    } else {
        return None;
    };
    // Version may include platform tags after another '-', take until first '-' with non-digit.
    let version = version_part
        .split('-')
        .next()
        .unwrap_or(version_part)
        .to_string();
    Some(RegistryMatch {
        ecosystem: Ecosystem::PyPI,
        package: package.replace('_', "-").to_lowercase(),
        version,
    })
}

fn parse_cargo(path: &str) -> Option<RegistryMatch> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // api/v1/crates/<package>/<version>/download
    if parts.len() >= 5 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "crates" {
        return Some(RegistryMatch {
            ecosystem: Ecosystem::Cargo,
            package: parts[3].to_string(),
            version: parts[4].to_string(),
        });
    }
    // static.crates.io/crates/<package>/<package>-<version>.crate
    if parts.len() >= 3 && parts[0] == "crates" {
        let filename = parts.last()?;
        let name_version = filename.strip_suffix(".crate")?;
        let (_, version) = name_version.rsplit_once('-')?;
        return Some(RegistryMatch {
            ecosystem: Ecosystem::Cargo,
            package: parts[1].to_string(),
            version: version.to_string(),
        });
    }
    None
}

fn parse_go(path: &str) -> Option<RegistryMatch> {
    // proxy.golang.org/<module>/@v/<version>.zip|.info|.mod
    let path = path.trim_start_matches('/');
    let at_v_idx = path.find("/@v/")?;
    let module = &path[..at_v_idx];
    let version_file = &path[at_v_idx + 4..];
    let version = version_file
        .strip_suffix(".zip")
        .or_else(|| version_file.strip_suffix(".info"))
        .or_else(|| version_file.strip_suffix(".mod"))?;
    Some(RegistryMatch {
        ecosystem: Ecosystem::Go,
        package: module.to_string(),
        version: version.to_string(),
    })
}

fn parse_maven(path: &str) -> Option<RegistryMatch> {
    // maven2/<group>/<artifact>/<version>/<artifact>-<version>.jar|.pom
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 4 || parts[0] != "maven2" {
        return None;
    }
    // Last 3 parts: artifact, version, filename
    let version = parts[parts.len() - 2].to_string();
    let artifact = parts[parts.len() - 3].to_string();
    let group = parts[1..parts.len() - 3].join(".");
    Some(RegistryMatch {
        ecosystem: Ecosystem::Maven,
        package: format!("{group}:{artifact}"),
        version,
    })
}

fn parse_nuget(path: &str) -> Option<RegistryMatch> {
    // v3-flatcontainer/<package>/<version>/<package>.<version>.nupkg
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() >= 3 && parts[0] == "v3-flatcontainer" {
        return Some(RegistryMatch {
            ecosystem: Ecosystem::NuGet,
            package: parts[1].to_string(),
            version: parts[2].to_string(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_scoped_package() {
        let m = detect_registry_pattern(
            "registry.npmjs.org",
            "/@babel/core/-/core-7.24.0.tgz",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::Npm);
        assert_eq!(m.package, "@babel/core");
        assert_eq!(m.version, "7.24.0");
    }

    #[test]
    fn npm_unscoped_package() {
        let m = detect_registry_pattern(
            "registry.npmjs.org",
            "/lodash/-/lodash-4.17.21.tgz",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::Npm);
        assert_eq!(m.package, "lodash");
        assert_eq!(m.version, "4.17.21");
    }

    #[test]
    fn pypi_tar_gz() {
        let m = detect_registry_pattern(
            "files.pythonhosted.org",
            "/packages/ab/cd/ef/requests-2.31.0.tar.gz",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::PyPI);
        assert_eq!(m.package, "requests");
        assert_eq!(m.version, "2.31.0");
    }

    #[test]
    fn pypi_wheel() {
        let m = detect_registry_pattern(
            "files.pythonhosted.org",
            "/packages/hash/numpy-1.26.4-cp311-cp311-linux_x86_64.whl",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::PyPI);
        assert_eq!(m.package, "numpy");
        assert_eq!(m.version, "1.26.4");
    }

    #[test]
    fn cargo_api() {
        let m = detect_registry_pattern(
            "crates.io",
            "/api/v1/crates/serde/1.0.200/download",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::Cargo);
        assert_eq!(m.package, "serde");
        assert_eq!(m.version, "1.0.200");
    }

    #[test]
    fn go_module() {
        let m = detect_registry_pattern(
            "proxy.golang.org",
            "/github.com/gin-gonic/gin/@v/v1.9.1.zip",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::Go);
        assert_eq!(m.package, "github.com/gin-gonic/gin");
        assert_eq!(m.version, "v1.9.1");
    }

    #[test]
    fn maven_jar() {
        let m = detect_registry_pattern(
            "repo1.maven.org",
            "/maven2/com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::Maven);
        assert_eq!(m.package, "com.google.guava:guava");
        assert_eq!(m.version, "32.1.3-jre");
    }

    #[test]
    fn nuget_package() {
        let m = detect_registry_pattern(
            "api.nuget.org",
            "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        )
        .unwrap();
        assert_eq!(m.ecosystem, Ecosystem::NuGet);
        assert_eq!(m.package, "newtonsoft.json");
        assert_eq!(m.version, "13.0.3");
    }

    #[test]
    fn unknown_host_returns_none() {
        assert!(detect_registry_pattern("example.com", "/some/path").is_none());
    }
}
