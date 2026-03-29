// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Async HTTP client for the cluster-internal NER service.
//!
//! Sends text to a Triton Inference Server wrapper running inside the customer's
//! AKS cluster. No data leaves the cluster boundary — the NER endpoint is a
//! Kubernetes ClusterIP service (e.g. `http://codicera-ner:8080`).

use crate::entities::EntityType;
use crate::policy::PiiDetection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Maximum response size from the NER service (512 KiB).
const MAX_RESPONSE_BYTES: usize = 524_288;

/// Default cache TTL for NER results.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// NER detect request payload.
#[derive(Serialize)]
struct NerRequest<'a> {
    text: &'a str,
    min_confidence: f32,
}

/// A single entity span from the NER service response.
#[derive(Debug, Deserialize)]
struct NerEntityResponse {
    /// Entity type label from the model (e.g. "person", "organization").
    #[serde(rename = "type")]
    entity_type: String,
    /// Matched text span.
    text: String,
    /// Character offset (start).
    start: usize,
    /// Character offset (end).
    end: usize,
    /// Detection confidence (0.0–1.0).
    confidence: f32,
}

/// NER detect response.
#[derive(Debug, Deserialize)]
struct NerResponse {
    entities: Vec<NerEntityResponse>,
    #[serde(default)]
    processing_time_ms: f64,
}

/// HTTP client for the cluster-internal NER inference service.
///
/// Follows the same fail-open pattern as `OsvClient` in `openshell-supply-chain`:
/// network errors produce a warning log and return an empty detection vec, never
/// blocking or crashing the relay.
pub struct NerClient {
    client: reqwest::Client,
    endpoint: String,
    cache: HashMap<u64, (Instant, Vec<PiiDetection>)>,
    cache_ttl: Duration,
}

impl NerClient {
    /// Create a new NER client targeting the given service endpoint.
    ///
    /// The endpoint should be a cluster-internal URL like
    /// `http://codicera-ner.codicera-default.svc.cluster.local:8080`.
    pub fn new(endpoint: String) -> Self {
        assert!(
            endpoint.starts_with("http://") || endpoint.starts_with("https://"),
            "NER endpoint must start with http:// or https://, got: {endpoint}"
        );
        Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build NER reqwest client"),
            endpoint,
            cache: HashMap::new(),
            cache_ttl: DEFAULT_CACHE_TTL,
        }
    }

    /// Detect named entities in text via the NER service.
    ///
    /// Returns `PiiDetection` spans compatible with regex detections so they
    /// can be merged by the engine. On any error, returns an empty vec (fail-open).
    pub async fn detect(&mut self, text: &str, min_confidence: f32) -> Vec<PiiDetection> {
        if text.is_empty() {
            return Vec::new();
        }

        // Check cache by text hash, evicting expired entries.
        let hash = hash_text(text);
        let expired = self
            .cache
            .get(&hash)
            .map(|(cached_at, _)| cached_at.elapsed() >= self.cache_ttl);
        match expired {
            Some(false) => {
                let detections = &self.cache[&hash].1;
                debug!(hash, count = detections.len(), "NER cache hit");
                return detections.clone();
            }
            Some(true) => {
                self.cache.remove(&hash);
            }
            None => {}
        }

        let url = format!("{}/api/v1/ner/detect", self.endpoint.trim_end_matches('/'));
        let body = NerRequest {
            text,
            min_confidence,
        };

        let result = self.client.post(&url).json(&body).send().await;

        let detections = match result {
            Ok(resp) if resp.status().is_success() => {
                let bytes = match resp.bytes().await {
                    Ok(b) if b.len() <= MAX_RESPONSE_BYTES => b,
                    Ok(b) => {
                        warn!(size = b.len(), "NER response too large, discarding");
                        return Vec::new();
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read NER response body");
                        return Vec::new();
                    }
                };

                match serde_json::from_slice::<NerResponse>(&bytes) {
                    Ok(ner_resp) => {
                        debug!(
                            entities = ner_resp.entities.len(),
                            processing_ms = ner_resp.processing_time_ms,
                            "NER detection complete"
                        );
                        ner_resp
                            .entities
                            .into_iter()
                            .filter_map(|e| {
                                let entity_type = EntityType::parse(&e.entity_type)?;
                                Some(PiiDetection {
                                    entity_type,
                                    span: e.start..e.end,
                                    matched_text: e.text,
                                    confidence: e.confidence,
                                })
                            })
                            .collect()
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to parse NER response JSON");
                        Vec::new()
                    }
                }
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "NER service returned non-success status");
                Vec::new()
            }
            Err(e) => {
                warn!(error = %e, "NER service request failed");
                Vec::new()
            }
        };

        // Cache the result.
        self.cache.insert(hash, (Instant::now(), detections.clone()));
        detections
    }
}

/// FNV-1a hash of text for cache keying.
fn hash_text(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_text_deterministic() {
        let h1 = hash_text("John Smith lives at 42 Oak Street");
        let h2 = hash_text("John Smith lives at 42 Oak Street");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_text_differs_for_different_input() {
        let h1 = hash_text("John Smith");
        let h2 = hash_text("Jane Doe");
        assert_ne!(h1, h2);
    }

    #[test]
    fn ner_entity_response_deserializes() {
        let json = r#"{"entities":[{"type":"person","text":"John","start":0,"end":4,"confidence":0.95}],"processing_time_ms":12.5}"#;
        let resp: NerResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.entities.len(), 1);
        assert_eq!(resp.entities[0].entity_type, "person");
        assert_eq!(resp.entities[0].confidence, 0.95);
    }

    #[test]
    fn ner_entity_response_unknown_type_filtered() {
        let json = r#"{"entities":[{"type":"unknown_entity","text":"foo","start":0,"end":3,"confidence":0.9}]}"#;
        let resp: NerResponse = serde_json::from_str(json).unwrap();
        // Unknown entity type should be filtered out by EntityType::parse returning None.
        let detections: Vec<PiiDetection> = resp
            .entities
            .into_iter()
            .filter_map(|e| {
                let entity_type = EntityType::parse(&e.entity_type)?;
                Some(PiiDetection {
                    entity_type,
                    span: e.start..e.end,
                    matched_text: e.text,
                    confidence: e.confidence,
                })
            })
            .collect();
        assert!(detections.is_empty());
    }
}
