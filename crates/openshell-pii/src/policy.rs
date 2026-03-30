// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PII policy configuration and detection result types.

use crate::entities::EntityType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::ops::Range;

/// Action to take when PII is detected for a given entity type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    /// Log detection but allow data through unmodified.
    Audit,
    /// Replace matched text with a redaction token.
    Redact,
    /// Deny the entire request/response.
    Block,
    /// Log a warning but allow data through.
    Warn,
}

/// A custom regex pattern defined by the user/org.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub name: String,
    pub pattern: String,
    pub action: PiiAction,
}

/// PII detection policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiPolicy {
    /// Default enforcement mode for entity types without explicit action.
    pub enforcement: String,
    /// Maximum body size to scan (bytes). Bodies larger than this are skipped.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Per-entity-type action overrides.
    #[serde(default)]
    pub entities: HashMap<EntityType, PiiAction>,
    /// Custom regex patterns.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,
    /// Cluster-internal NER service endpoint (e.g. `http://codicera-ner:8080`).
    /// When `Some`, the NER service is called for Tier 2 detection.
    #[serde(default)]
    pub ner_endpoint: Option<String>,
    /// Minimum confidence threshold for NER detections (0.0–1.0).
    #[serde(default = "default_ner_min_confidence")]
    pub ner_min_confidence: f32,
    /// When `true`, NER runs asynchronously (detect-and-log) instead of inline
    /// (detect-and-block/redact). Use async for audit/warn policies where latency
    /// matters more than inline enforcement.
    #[serde(default)]
    pub ner_async: bool,
}

fn default_max_body_bytes() -> usize {
    1_048_576 // 1 MiB
}

fn default_ner_min_confidence() -> f32 {
    0.7
}

impl Default for PiiPolicy {
    fn default() -> Self {
        Self {
            enforcement: "audit".to_string(),
            max_body_bytes: default_max_body_bytes(),
            entities: HashMap::new(),
            custom_patterns: Vec::new(),
            ner_endpoint: None,
            ner_min_confidence: default_ner_min_confidence(),
            ner_async: false,
        }
    }
}

impl PiiPolicy {
    /// Get the action for a given entity type, falling back to the default enforcement.
    pub fn action_for(&self, entity_type: EntityType) -> PiiAction {
        self.entities.get(&entity_type).copied().unwrap_or_else(|| {
            match self.enforcement.as_str() {
                "redact" => PiiAction::Redact,
                "block" => PiiAction::Block,
                _ => PiiAction::Audit,
            }
        })
    }

    /// Returns `true` if a NER service endpoint is configured.
    pub fn ner_enabled(&self) -> bool {
        self.ner_endpoint.is_some()
    }
}

/// A single PII detection within a body.
///
/// Custom `Debug` impl redacts `matched_text` to prevent PII leaking into logs.
#[derive(Clone)]
pub struct PiiDetection {
    /// The type of PII entity detected.
    pub entity_type: EntityType,
    /// Byte range within the body.
    pub span: Range<usize>,
    /// The matched text (redacted in Debug output).
    pub matched_text: String,
    /// Detection confidence (0.0–1.0).
    pub confidence: f32,
}

impl fmt::Debug for PiiDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PiiDetection")
            .field("entity_type", &self.entity_type)
            .field("span", &self.span)
            .field("matched_text", &"[REDACTED]")
            .field("confidence", &self.confidence)
            .finish()
    }
}

/// Result of applying the PII policy to a body.
#[derive(Debug)]
pub enum PiiApplyResult {
    /// No PII detected.
    Clean,
    /// PII detected, logged only (audit mode).
    Audited(Vec<PiiDetection>),
    /// PII detected and redacted in the body.
    Redacted {
        count: usize,
        detections: Vec<PiiDetection>,
    },
    /// PII detected, request/response should be blocked.
    Blocked { detections: Vec<PiiDetection> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_for_defaults_to_enforcement() {
        let policy = PiiPolicy {
            enforcement: "redact".to_string(),
            ..Default::default()
        };
        assert_eq!(policy.action_for(EntityType::Ssn), PiiAction::Redact);
        assert_eq!(policy.action_for(EntityType::Email), PiiAction::Redact);
    }

    #[test]
    fn action_for_entity_override() {
        let mut entities = HashMap::new();
        entities.insert(EntityType::CreditCard, PiiAction::Block);
        let policy = PiiPolicy {
            enforcement: "audit".to_string(),
            entities,
            ..Default::default()
        };
        assert_eq!(policy.action_for(EntityType::CreditCard), PiiAction::Block);
        assert_eq!(policy.action_for(EntityType::Ssn), PiiAction::Audit);
    }

    #[test]
    fn action_for_block_enforcement() {
        let policy = PiiPolicy {
            enforcement: "block".to_string(),
            ..Default::default()
        };
        assert_eq!(policy.action_for(EntityType::Email), PiiAction::Block);
    }

    #[test]
    fn action_for_unknown_enforcement_falls_back_to_audit() {
        let policy = PiiPolicy {
            enforcement: "unknown".to_string(),
            ..Default::default()
        };
        assert_eq!(policy.action_for(EntityType::Ssn), PiiAction::Audit);
    }

    #[test]
    fn default_policy_values() {
        let p = PiiPolicy::default();
        assert_eq!(p.enforcement, "audit");
        assert_eq!(p.max_body_bytes, 1_048_576);
        assert!(p.entities.is_empty());
        assert!(p.custom_patterns.is_empty());
        assert!(p.ner_endpoint.is_none());
        assert!((p.ner_min_confidence - 0.7).abs() < f32::EPSILON);
        assert!(!p.ner_async);
    }

    #[test]
    fn serde_round_trip() {
        let yaml = r#"
enforcement: redact
max_body_bytes: 2097152
entities:
  ssn: block
  credit_card: redact
custom_patterns:
  - name: employee_id
    pattern: "EMP-\\d{6}"
    action: redact
ner_endpoint: "http://ner:8080"
ner_min_confidence: 0.8
ner_async: true
"#;
        let policy: PiiPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.enforcement, "redact");
        assert_eq!(policy.max_body_bytes, 2_097_152);
        assert_eq!(
            policy.entities.get(&EntityType::Ssn),
            Some(&PiiAction::Block)
        );
        assert_eq!(
            policy.entities.get(&EntityType::CreditCard),
            Some(&PiiAction::Redact)
        );
        assert_eq!(policy.custom_patterns.len(), 1);
        assert_eq!(policy.custom_patterns[0].name, "employee_id");
        assert_eq!(policy.ner_endpoint.as_deref(), Some("http://ner:8080"));
        assert!((policy.ner_min_confidence - 0.8).abs() < f32::EPSILON);
        assert!(policy.ner_async);

        // Round-trip through JSON
        let json = serde_json::to_string(&policy).unwrap();
        let restored: PiiPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.enforcement, "redact");
        assert_eq!(restored.max_body_bytes, 2_097_152);
    }

    #[test]
    fn pii_detection_debug_redacts_matched_text() {
        let det = PiiDetection {
            entity_type: EntityType::Ssn,
            span: 0..11,
            matched_text: "123-45-6789".to_string(),
            confidence: 0.95,
        };
        let debug = format!("{det:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("123-45-6789"));
    }
}
