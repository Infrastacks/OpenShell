// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regex-based PII detection engine for OpenShell L7 inspection.
//!
//! Detects personally identifiable information and secrets in HTTP request/response
//! bodies. Enforcement is policy-driven: audit (log only), redact (replace matches),
//! or block (deny the request/response).

mod engine;
mod entities;
mod policy;
mod redactor;

pub use engine::PiiEngine;
pub use entities::EntityType;
pub use policy::{CustomPattern, PiiAction, PiiApplyResult, PiiDetection, PiiPolicy};
pub use redactor::redact;
