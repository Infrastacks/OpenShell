// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PII redaction — replaces matched text with redaction tokens.

use crate::policy::PiiDetection;

/// Redact all detections in the body, processing right-to-left to preserve offsets.
///
/// Returns the number of redactions applied.
pub fn redact(body: &mut Vec<u8>, detections: &[PiiDetection]) -> usize {
    // Sort by span start descending so we replace right-to-left.
    let mut sorted: Vec<&PiiDetection> = detections.iter().collect();
    sorted.sort_by(|a, b| b.span.start.cmp(&a.span.start));

    let mut count = 0;
    for detection in sorted {
        let replacement = format!("[REDACTED:{}]", detection.entity_type);
        let start = detection.span.start;
        let end = detection.span.end.min(body.len());
        if start < end && start < body.len() {
            body.splice(start..end, replacement.bytes());
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::EntityType;

    fn detection(entity: EntityType, start: usize, end: usize, text: &str) -> PiiDetection {
        PiiDetection {
            entity_type: entity,
            span: start..end,
            matched_text: text.to_string(),
            confidence: 0.9,
        }
    }

    #[test]
    fn redact_single() {
        let mut body = b"SSN is 123-45-6789 here".to_vec();
        let detections = vec![detection(EntityType::Ssn, 7, 18, "123-45-6789")];
        let count = redact(&mut body, &detections);
        assert_eq!(count, 1);
        assert_eq!(String::from_utf8_lossy(&body), "SSN is [REDACTED:ssn] here");
    }

    #[test]
    fn redact_multiple_preserves_offsets() {
        let mut body = b"A 123-45-6789 B 078-05-1120 C".to_vec();
        let detections = vec![
            detection(EntityType::Ssn, 2, 13, "123-45-6789"),
            detection(EntityType::Ssn, 16, 27, "078-05-1120"),
        ];
        let count = redact(&mut body, &detections);
        assert_eq!(count, 2);
        let result = String::from_utf8_lossy(&body);
        assert!(result.contains("[REDACTED:ssn]"));
        assert!(!result.contains("123-45-6789"));
        assert!(!result.contains("078-05-1120"));
    }

    #[test]
    fn redact_empty_detections() {
        let mut body = b"no pii here".to_vec();
        let count = redact(&mut body, &[]);
        assert_eq!(count, 0);
        assert_eq!(String::from_utf8_lossy(&body), "no pii here");
    }
}
