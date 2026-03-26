// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PII detection engine — runs compiled patterns against byte buffers.

use crate::entities::{builtin_patterns, EntityPattern, EntityType};
use crate::policy::{PiiAction, PiiApplyResult, PiiDetection, PiiPolicy};
use crate::redactor;
use regex::Regex;
use tracing::debug;

/// Compiled PII detection engine.
pub struct PiiEngine {
    /// Built-in patterns filtered to only enabled entity types.
    builtins: Vec<EntityPattern>,
    /// Custom patterns compiled from policy.
    custom: Vec<(String, Regex, PiiAction)>,
    /// The policy driving enforcement decisions.
    policy: PiiPolicy,
}

impl PiiEngine {
    /// Create a new engine from a policy configuration.
    ///
    /// Only compiles patterns for entity types that are configured in the policy.
    /// If the policy has no entity overrides, all built-in types are enabled
    /// using the default enforcement mode.
    pub fn new(policy: &PiiPolicy) -> Self {
        let builtins: Vec<EntityPattern> = builtin_patterns()
            .into_iter()
            .filter(|p| {
                // Include if explicitly configured OR if no entities are specified (scan all).
                policy.entities.is_empty() || policy.entities.contains_key(&p.entity_type)
            })
            .collect();

        let custom: Vec<(String, Regex, PiiAction)> = policy
            .custom_patterns
            .iter()
            .filter_map(|cp| {
                match Regex::new(&cp.pattern) {
                    Ok(re) => Some((cp.name.clone(), re, cp.action)),
                    Err(e) => {
                        tracing::warn!(
                            pattern_name = %cp.name,
                            error = %e,
                            "Failed to compile custom PII pattern, skipping"
                        );
                        None
                    }
                }
            })
            .collect();

        debug!(
            builtin_count = builtins.len(),
            custom_count = custom.len(),
            enforcement = %policy.enforcement,
            "PII engine initialized"
        );

        Self {
            builtins,
            custom,
            policy: policy.clone(),
        }
    }

    /// Detect PII entities in a byte buffer.
    ///
    /// Returns an empty vec if the body exceeds `max_body_bytes` or is not valid UTF-8.
    pub fn detect(&self, body: &[u8]) -> Vec<PiiDetection> {
        if body.len() > self.policy.max_body_bytes {
            debug!(
                body_len = body.len(),
                max = self.policy.max_body_bytes,
                "Body exceeds max size for PII scanning, skipping"
            );
            return Vec::new();
        }

        // PII detection requires text — binary bodies are skipped.
        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => {
                debug!("Body is not valid UTF-8, skipping PII scan");
                return Vec::new();
            }
        };

        let mut detections = Vec::new();

        // Run built-in patterns.
        for pattern in &self.builtins {
            for m in pattern.regex.find_iter(text) {
                let matched_text = m.as_str();
                // Run optional validator (e.g., Luhn for credit cards).
                if let Some(validator) = pattern.validator {
                    if !validator(matched_text) {
                        continue;
                    }
                }
                detections.push(PiiDetection {
                    entity_type: pattern.entity_type,
                    span: m.start()..m.end(),
                    matched_text: matched_text.to_string(),
                    confidence: pattern.confidence,
                });
            }
        }

        // Run custom patterns (use a synthetic entity type — ApiKey as placeholder).
        for (name, regex, _action) in &self.custom {
            for m in regex.find_iter(text) {
                detections.push(PiiDetection {
                    entity_type: EntityType::ApiKey, // Custom patterns map to ApiKey for now
                    span: m.start()..m.end(),
                    matched_text: m.as_str().to_string(),
                    confidence: 0.8,
                });
                debug!(pattern_name = %name, "Custom PII pattern matched");
            }
        }

        detections
    }

    /// Detect and apply the policy to a mutable body buffer.
    ///
    /// Returns the enforcement result: clean, audited, redacted, or blocked.
    pub fn apply(&self, body: &mut Vec<u8>, detections: &[PiiDetection]) -> PiiApplyResult {
        if detections.is_empty() {
            return PiiApplyResult::Clean;
        }

        // Check if any detection triggers a block.
        let should_block = detections.iter().any(|d| {
            self.policy.action_for(d.entity_type) == PiiAction::Block
        });

        if should_block {
            return PiiApplyResult::Blocked {
                detections: detections.to_vec(),
            };
        }

        // Check if any detection triggers redaction.
        let redact_detections: Vec<&PiiDetection> = detections
            .iter()
            .filter(|d| self.policy.action_for(d.entity_type) == PiiAction::Redact)
            .collect();

        if !redact_detections.is_empty() {
            let to_redact: Vec<PiiDetection> = redact_detections.into_iter().cloned().collect();
            let count = redactor::redact(body, &to_redact);
            return PiiApplyResult::Redacted {
                count,
                detections: detections.to_vec(),
            };
        }

        // Everything is audit/warn — log only.
        PiiApplyResult::Audited(detections.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn audit_policy() -> PiiPolicy {
        PiiPolicy {
            enforcement: "audit".to_string(),
            max_body_bytes: 1_048_576,
            entities: HashMap::new(),
            custom_patterns: Vec::new(),
        }
    }

    fn redact_policy() -> PiiPolicy {
        let mut entities = HashMap::new();
        entities.insert(EntityType::Ssn, PiiAction::Redact);
        entities.insert(EntityType::CreditCard, PiiAction::Redact);
        PiiPolicy {
            enforcement: "redact".to_string(),
            max_body_bytes: 1_048_576,
            entities,
            custom_patterns: Vec::new(),
        }
    }

    fn block_policy() -> PiiPolicy {
        let mut entities = HashMap::new();
        entities.insert(EntityType::CreditCard, PiiAction::Block);
        entities.insert(EntityType::Ssn, PiiAction::Audit);
        PiiPolicy {
            enforcement: "block".to_string(),
            max_body_bytes: 1_048_576,
            entities,
            custom_patterns: Vec::new(),
        }
    }

    #[test]
    fn detect_ssn_in_body() {
        let engine = PiiEngine::new(&audit_policy());
        let body = b"User SSN: 123-45-6789";
        let detections = engine.detect(body);
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.entity_type == EntityType::Ssn));
    }

    #[test]
    fn detect_email_in_body() {
        let engine = PiiEngine::new(&audit_policy());
        let body = b"Contact: admin@example.com for help";
        let detections = engine.detect(body);
        assert!(detections.iter().any(|d| d.entity_type == EntityType::Email));
    }

    #[test]
    fn detect_credit_card_with_luhn() {
        let engine = PiiEngine::new(&audit_policy());
        // 4111111111111111 passes Luhn
        let body = b"Card: 4111111111111111";
        let detections = engine.detect(body);
        assert!(detections.iter().any(|d| d.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn reject_credit_card_failing_luhn() {
        let engine = PiiEngine::new(&audit_policy());
        // 4111111111111112 fails Luhn
        let body = b"Card: 4111111111111112";
        let detections = engine.detect(body);
        assert!(!detections.iter().any(|d| d.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detect_aws_key() {
        let engine = PiiEngine::new(&audit_policy());
        let body = b"key=AKIAIOSFODNN7EXAMPLE";
        let detections = engine.detect(body);
        assert!(detections.iter().any(|d| d.entity_type == EntityType::AwsAccessKey));
    }

    #[test]
    fn detect_jwt() {
        let engine = PiiEngine::new(&audit_policy());
        let body = b"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let detections = engine.detect(body);
        assert!(detections.iter().any(|d| d.entity_type == EntityType::Jwt));
    }

    #[test]
    fn skip_oversized_body() {
        let policy = PiiPolicy {
            max_body_bytes: 10,
            ..audit_policy()
        };
        let engine = PiiEngine::new(&policy);
        let body = b"SSN: 123-45-6789 this is over 10 bytes";
        let detections = engine.detect(body);
        assert!(detections.is_empty());
    }

    #[test]
    fn skip_binary_body() {
        let engine = PiiEngine::new(&audit_policy());
        let body: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01];
        let detections = engine.detect(&body);
        assert!(detections.is_empty());
    }

    #[test]
    fn apply_audit_returns_audited() {
        let engine = PiiEngine::new(&audit_policy());
        let mut body = b"SSN: 123-45-6789".to_vec();
        let detections = engine.detect(&body);
        let result = engine.apply(&mut body, &detections);
        assert!(matches!(result, PiiApplyResult::Audited(_)));
        // Body unchanged in audit mode.
        assert_eq!(String::from_utf8_lossy(&body), "SSN: 123-45-6789");
    }

    #[test]
    fn apply_redact_modifies_body() {
        let engine = PiiEngine::new(&redact_policy());
        let mut body = b"SSN: 123-45-6789".to_vec();
        let detections = engine.detect(&body);
        let result = engine.apply(&mut body, &detections);
        assert!(matches!(result, PiiApplyResult::Redacted { .. }));
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("[REDACTED:ssn]"));
        assert!(!text.contains("123-45-6789"));
    }

    #[test]
    fn apply_block_does_not_modify_body() {
        let engine = PiiEngine::new(&block_policy());
        let mut body = b"Card: 4111111111111111".to_vec();
        let detections = engine.detect(&body);
        let result = engine.apply(&mut body, &detections);
        assert!(matches!(result, PiiApplyResult::Blocked { .. }));
    }

    #[test]
    fn clean_body_returns_clean() {
        let engine = PiiEngine::new(&audit_policy());
        let mut body = b"No PII here whatsoever".to_vec();
        let detections = engine.detect(&body);
        let result = engine.apply(&mut body, &detections);
        assert!(matches!(result, PiiApplyResult::Clean));
    }

    #[test]
    fn custom_pattern_detects() {
        let policy = PiiPolicy {
            custom_patterns: vec![crate::policy::CustomPattern {
                name: "internal_id".to_string(),
                pattern: r"CORP-\d{8}".to_string(),
                action: PiiAction::Redact,
            }],
            ..audit_policy()
        };
        let engine = PiiEngine::new(&policy);
        let body = b"Employee CORP-12345678 logged in";
        let detections = engine.detect(body);
        assert!(!detections.is_empty());
    }
}
