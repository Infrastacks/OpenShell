use openshell_pii::{CustomPattern, EntityType, NerClient, PiiAction, PiiEngine, PiiPolicy};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

/// Top-level policy YAML structure (matches openshell-policy format).
#[derive(Deserialize)]
struct PolicyFile {
    #[allow(dead_code)]
    version: u32,
    #[serde(default)]
    pii: Option<PiiSection>,
}

/// PII section of the policy YAML.
#[derive(Deserialize)]
pub struct PiiSection {
    #[serde(default = "default_audit")]
    pub enforcement: String,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub entities: HashMap<String, String>,
    #[serde(default)]
    pub custom_patterns: Vec<CustomPatternDef>,
    #[serde(default)]
    pub ner_endpoint: Option<String>,
    #[serde(default = "default_ner_confidence")]
    pub ner_min_confidence: f64,
    #[serde(default)]
    pub ner_async: bool,
}

#[derive(Deserialize)]
pub struct CustomPatternDef {
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_audit")]
    pub action: String,
}

fn default_audit() -> String {
    "audit".to_string()
}
fn default_max_body() -> usize {
    1_048_576
}
fn default_ner_confidence() -> f64 {
    0.7
}

fn parse_action(s: &str) -> PiiAction {
    match s {
        "redact" => PiiAction::Redact,
        "block" => PiiAction::Block,
        "warn" => PiiAction::Warn,
        _ => PiiAction::Audit,
    }
}

/// Convert a parsed PII section into a runtime PiiPolicy.
fn section_to_policy(sec: &PiiSection) -> PiiPolicy {
    let entities: HashMap<EntityType, PiiAction> = sec
        .entities
        .iter()
        .filter_map(|(name, action)| {
            let et = EntityType::parse(name)?;
            Some((et, parse_action(action)))
        })
        .collect();

    let custom_patterns: Vec<CustomPattern> = sec
        .custom_patterns
        .iter()
        .map(|cp| CustomPattern {
            name: cp.name.clone(),
            pattern: cp.pattern.clone(),
            action: parse_action(&cp.action),
        })
        .collect();

    PiiPolicy {
        enforcement: sec.enforcement.clone(),
        max_body_bytes: sec.max_body_bytes,
        entities,
        custom_patterns,
        ner_endpoint: sec.ner_endpoint.clone(),
        ner_min_confidence: sec.ner_min_confidence as f32,
        ner_async: sec.ner_async,
    }
}

/// Load a PII engine from a YAML policy file. Returns `None` if the file has no `pii` section.
pub fn load_engine(path: &Path) -> Result<Option<PiiEngine>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let file: PolicyFile = serde_yaml::from_str(&content).map_err(|e| format!("parse YAML: {e}"))?;
    Ok(file.pii.as_ref().map(|sec| {
        let policy = section_to_policy(sec);
        PiiEngine::new(&policy)
    }))
}

/// Extract ner_endpoint from a policy file without building a full engine.
fn load_ner_endpoint(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let file: PolicyFile = serde_yaml::from_str(&content).ok()?;
    file.pii.and_then(|sec| sec.ner_endpoint)
}

/// Shared engine handle — `None` means passthrough mode (no PII scanning).
pub type SharedEngine = Arc<RwLock<Option<PiiEngine>>>;

/// Shared NER client handle — `None` means NER is not configured.
pub type SharedNerClient = Arc<Mutex<Option<NerClient>>>;

/// Create a shared engine, loading from the policy file if it exists.
pub fn init_engine(path: Option<&Path>) -> SharedEngine {
    let engine = path.and_then(|p| {
        if !p.exists() {
            info!(path = %p.display(), "PII policy file not found, starting in passthrough mode");
            return None;
        }
        match load_engine(p) {
            Ok(e) => {
                if e.is_some() {
                    info!(path = %p.display(), "PII engine loaded from policy file");
                } else {
                    info!(path = %p.display(), "Policy file has no pii section, passthrough mode");
                }
                e
            }
            Err(e) => {
                warn!(error = %e, "Failed to load PII policy, starting in passthrough mode");
                None
            }
        }
    });
    Arc::new(RwLock::new(engine))
}

/// Create a shared NER client from the policy file's ner_endpoint.
pub fn init_ner_client(path: Option<&Path>) -> SharedNerClient {
    let client = path.and_then(|p| {
        let endpoint = load_ner_endpoint(p)?;
        info!(endpoint = %endpoint, "NER client initialized");
        Some(NerClient::new(endpoint))
    });
    Arc::new(Mutex::new(client))
}

/// Spawn a background task that polls the policy file for changes.
pub fn spawn_watcher(
    path: PathBuf,
    engine: SharedEngine,
    ner_client: SharedNerClient,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let current_mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());

            // Detect new file or modified file.
            let changed = match (last_mtime, current_mtime) {
                (None, Some(_)) => true,
                (Some(prev), Some(cur)) => cur != prev,
                _ => false,
            };

            if changed {
                match load_engine(&path) {
                    Ok(new_engine) => {
                        // Update NER client if endpoint changed.
                        let new_ner = load_ner_endpoint(&path).map(NerClient::new);
                        *ner_client.lock().await = new_ner;
                        *engine.write().await = new_engine;
                        info!(path = %path.display(), "PII policy reloaded");
                    }
                    Err(e) => warn!(error = %e, "Failed to reload PII policy"),
                }
                last_mtime = current_mtime;
            }
        }
    })
}
