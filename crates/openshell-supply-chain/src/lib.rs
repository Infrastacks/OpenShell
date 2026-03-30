// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supply chain security engine for OpenShell L7 inspection.
//!
//! Detects package registry traffic in the L7 proxy, evaluates packages against
//! vulnerability databases (OSV), license policies, and denylists. Enforcement
//! is policy-driven: audit (log only) or enforce (block installs that violate policy).

mod denylist;
mod license;
mod osv_client;
mod policy;
mod registry;
mod version;

pub use denylist::check_denylist;
pub use license::{LicenseStatus, check_license};
pub use osv_client::{
    OsvClient, OsvQueryError, Vulnerability, classify_severity, extract_fixed_version,
};
pub use policy::{
    Decision, DenylistEntry, LicensePolicy, SupplyChainEngine, SupplyChainPolicy,
    SupplyChainResult, VersionPin, VulnCounts, VulnDetail, VulnThresholds,
};
pub use registry::{Ecosystem, RegistryMatch, detect_registry_pattern};
pub use version::check_version_pin;
