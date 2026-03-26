// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Two-tier PII detection engine for OpenShell L7 inspection.
//!
//! **Tier 1 (regex)**: Detects structured PII (SSNs, credit cards, API keys) via
//! compiled regex patterns. Always runs, zero external dependencies.
//!
//! **Tier 2 (NER)**: Detects unstructured PII (names, addresses, medical terms) via
//! a cluster-internal ML model. Requires the `ner` feature flag and a running NER
//! service endpoint.
//!
//! Enforcement is policy-driven: audit (log only), redact (replace matches),
//! or block (deny the request/response).

mod engine;
mod entities;
mod policy;
mod redactor;

#[cfg(feature = "ner")]
pub mod ner_client;

pub use engine::{merge_detections, PiiEngine};
pub use entities::EntityType;
pub use policy::{CustomPattern, PiiAction, PiiApplyResult, PiiDetection, PiiPolicy};
pub use redactor::redact;

#[cfg(feature = "ner")]
pub use ner_client::NerClient;
