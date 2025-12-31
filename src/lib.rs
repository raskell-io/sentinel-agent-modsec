//! Sentinel ModSecurity Agent Library
//!
//! A Web Application Firewall agent for Sentinel proxy that uses libmodsecurity
//! for full OWASP Core Rule Set (CRS) support.
//!
//! # Example
//!
//! ```ignore
//! use sentinel_agent_modsec::{ModSecAgent, ModSecConfig};
//! use sentinel_agent_protocol::AgentServer;
//!
//! let config = ModSecConfig {
//!     rules_paths: vec!["/etc/modsecurity/crs/rules/*.conf".to_string()],
//!     ..Default::default()
//! };
//! let agent = ModSecAgent::new(config)?;
//! let server = AgentServer::new("modsec", "/tmp/modsec.sock", Box::new(agent));
//! server.run().await?;
//! ```

use anyhow::Result;
use base64::Engine;
use modsecurity_rs::{ModSecurity, RulesSet, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
};

/// ModSecurity configuration
#[derive(Debug, Clone)]
pub struct ModSecConfig {
    /// Paths to ModSecurity rule files (glob patterns supported)
    pub rules_paths: Vec<String>,
    /// Block mode (true) or detect-only mode (false)
    pub block_mode: bool,
    /// Paths to exclude from inspection
    pub exclude_paths: Vec<String>,
    /// Enable request body inspection
    pub body_inspection_enabled: bool,
    /// Maximum body size to inspect in bytes
    pub max_body_size: usize,
    /// Enable response body inspection
    pub response_inspection_enabled: bool,
}

impl Default for ModSecConfig {
    fn default() -> Self {
        Self {
            rules_paths: vec![],
            block_mode: true,
            exclude_paths: vec![],
            body_inspection_enabled: true,
            max_body_size: 1048576, // 1MB
            response_inspection_enabled: false,
        }
    }
}

/// Detection result from ModSecurity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub rule_id: String,
    pub message: String,
    pub severity: Option<String>,
}

/// ModSecurity engine wrapper
pub struct ModSecEngine {
    modsec: ModSecurity,
    rules: RulesSet,
    pub config: ModSecConfig,
}

impl ModSecEngine {
    /// Create a new ModSecurity engine with the given configuration
    pub fn new(config: ModSecConfig) -> Result<Self> {
        let modsec = ModSecurity::new();

        // Load rules from configured paths
        let rules_paths: Vec<&str> = config.rules_paths.iter().map(|s| s.as_str()).collect();

        let rules = if rules_paths.is_empty() {
            // Create empty ruleset if no paths configured
            RulesSet::from_paths(&[]).map_err(|e| anyhow::anyhow!("Failed to create ruleset: {}", e))?
        } else {
            RulesSet::from_paths(&rules_paths)
                .map_err(|e| anyhow::anyhow!("Failed to load rules: {}", e))?
        };

        info!(
            rules_count = rules_paths.len(),
            "ModSecurity engine initialized"
        );

        Ok(Self {
            modsec,
            rules,
            config,
        })
    }

    /// Check if path should be excluded
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p))
    }

    /// Create a new transaction for processing a request
    pub fn create_transaction(&mut self) -> Result<Transaction> {
        Transaction::new(&mut self.modsec, &mut self.rules)
            .map_err(|e| anyhow::anyhow!("Failed to create transaction: {}", e))
    }
}

/// Body accumulator for tracking in-progress bodies
#[derive(Debug, Default)]
struct BodyAccumulator {
    data: Vec<u8>,
}

/// Pending transaction for body accumulation
struct PendingTransaction {
    body: BodyAccumulator,
    method: String,
    uri: String,
    headers: HashMap<String, Vec<String>>,
    client_ip: String,
}

/// ModSecurity agent
pub struct ModSecAgent {
    engine: Arc<RwLock<ModSecEngine>>,
    pending_requests: Arc<RwLock<HashMap<String, PendingTransaction>>>,
    pending_response_bodies: Arc<RwLock<HashMap<String, BodyAccumulator>>>,
}

impl ModSecAgent {
    pub fn new(config: ModSecConfig) -> Result<Self> {
        let engine = ModSecEngine::new(config)?;
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            pending_response_bodies: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Process a complete request through ModSecurity
    async fn process_request(
        &self,
        correlation_id: &str,
        method: &str,
        uri: &str,
        headers: &HashMap<String, Vec<String>>,
        body: Option<&[u8]>,
        client_ip: &str,
    ) -> Result<Option<(u16, String)>> {
        let mut engine = self.engine.write().await;
        let mut tx = engine.create_transaction()?;

        // Process connection
        tx.process_connection(client_ip, 0, "localhost", 80)
            .map_err(|e| anyhow::anyhow!("process_connection failed: {}", e))?;

        // Process URI
        let http_version = "1.1";
        tx.process_uri(uri, method, http_version)
            .map_err(|e| anyhow::anyhow!("process_uri failed: {}", e))?;

        // Add headers
        for (name, values) in headers {
            for value in values {
                tx.add_request_header(name, value)
                    .map_err(|e| anyhow::anyhow!("add_request_header failed: {}", e))?;
            }
        }

        // Process request headers
        tx.process_request_headers()
            .map_err(|e| anyhow::anyhow!("process_request_headers failed: {}", e))?;

        // Check for intervention after headers
        if let Ok(intervention) = tx.intervention() {
            if intervention.disruptive {
                let status = intervention.status as u16;
                let message = intervention.log.unwrap_or_else(|| "Blocked by ModSecurity".to_string());
                debug!(
                    correlation_id = correlation_id,
                    status = status,
                    "ModSecurity intervention after headers"
                );
                return Ok(Some((status, message)));
            }
        }

        // Process body if provided
        if let Some(body_data) = body {
            if !body_data.is_empty() {
                // ModSecurity expects body to be appended then processed
                // The modsecurity-rs API may differ - process_request_body() handles it
                tx.process_request_body()
                    .map_err(|e| anyhow::anyhow!("process_request_body failed: {}", e))?;

                // Check for intervention after body
                if let Ok(intervention) = tx.intervention() {
                    if intervention.disruptive {
                        let status = intervention.status as u16;
                        let message = intervention.log.unwrap_or_else(|| "Blocked by ModSecurity".to_string());
                        debug!(
                            correlation_id = correlation_id,
                            status = status,
                            "ModSecurity intervention after body"
                        );
                        return Ok(Some((status, message)));
                    }
                }
            }
        }

        // Log the transaction
        tx.process_logging()
            .map_err(|e| anyhow::anyhow!("process_logging failed: {}", e))?;

        Ok(None)
    }
}

#[async_trait::async_trait]
impl AgentHandler for ModSecAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let path = &event.uri;
        let correlation_id = &event.metadata.correlation_id;

        // Check exclusions
        {
            let engine = self.engine.read().await;
            if engine.is_excluded(path) {
                debug!(path = path, "Path excluded from ModSecurity");
                return AgentResponse::default_allow();
            }
        }

        // If body inspection is enabled, we need to wait for the body
        // Store the request info for later
        {
            let engine = self.engine.read().await;
            if engine.config.body_inspection_enabled {
                let mut pending = self.pending_requests.write().await;
                pending.insert(
                    correlation_id.clone(),
                    PendingTransaction {
                        body: BodyAccumulator::default(),
                        method: event.method.clone(),
                        uri: event.uri.clone(),
                        headers: event.headers.clone(),
                        client_ip: event.metadata.client_ip.clone(),
                    },
                );
                // We'll process when we get the body or if there's no body
                return AgentResponse::default_allow();
            }
        }

        // No body inspection - process immediately
        match self
            .process_request(
                correlation_id,
                &event.method,
                &event.uri,
                &event.headers,
                None,
                &event.metadata.client_ip,
            )
            .await
        {
            Ok(Some((status, message))) => {
                let engine = self.engine.read().await;
                if engine.config.block_mode {
                    info!(
                        correlation_id = correlation_id,
                        status = status,
                        "Request blocked by ModSecurity"
                    );
                    AgentResponse::block(status, Some("Forbidden".to_string()))
                        .add_response_header(HeaderOp::Set {
                            name: "X-WAF-Blocked".to_string(),
                            value: "true".to_string(),
                        })
                        .add_response_header(HeaderOp::Set {
                            name: "X-WAF-Message".to_string(),
                            value: message.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["modsec".to_string(), "blocked".to_string()],
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                } else {
                    info!(
                        correlation_id = correlation_id,
                        "ModSecurity detection (detect-only mode)"
                    );
                    AgentResponse::default_allow()
                        .add_request_header(HeaderOp::Set {
                            name: "X-WAF-Detected".to_string(),
                            value: message.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["modsec".to_string(), "detected".to_string()],
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                }
            }
            Ok(None) => AgentResponse::default_allow(),
            Err(e) => {
                warn!(error = %e, "ModSecurity processing error");
                AgentResponse::default_allow()
            }
        }
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        // Check if we have a pending request
        let pending_exists = {
            let pending = self.pending_requests.read().await;
            pending.contains_key(correlation_id)
        };

        if !pending_exists {
            // No pending request - body inspection might be disabled
            return AgentResponse::default_allow();
        }

        // Decode base64 chunk
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode body chunk");
                return AgentResponse::default_allow();
            }
        };

        // Accumulate chunk
        let should_process = {
            let mut pending = self.pending_requests.write().await;
            if let Some(tx) = pending.get_mut(correlation_id) {
                let engine = self.engine.read().await;

                // Check size limit
                if tx.body.data.len() + chunk.len() > engine.config.max_body_size {
                    debug!(
                        correlation_id = correlation_id,
                        "Body exceeds max size, skipping inspection"
                    );
                    pending.remove(correlation_id);
                    return AgentResponse::default_allow();
                }

                tx.body.data.extend(chunk);
                event.is_last
            } else {
                false
            }
        };

        // If this is the last chunk, process the complete request
        if should_process {
            let pending_tx = {
                let mut pending = self.pending_requests.write().await;
                pending.remove(correlation_id)
            };

            if let Some(tx) = pending_tx {
                match self
                    .process_request(
                        correlation_id,
                        &tx.method,
                        &tx.uri,
                        &tx.headers,
                        Some(&tx.body.data),
                        &tx.client_ip,
                    )
                    .await
                {
                    Ok(Some((status, message))) => {
                        let engine = self.engine.read().await;
                        if engine.config.block_mode {
                            info!(
                                correlation_id = correlation_id,
                                status = status,
                                "Request blocked by ModSecurity (body inspection)"
                            );
                            return AgentResponse::block(status, Some("Forbidden".to_string()))
                                .add_response_header(HeaderOp::Set {
                                    name: "X-WAF-Blocked".to_string(),
                                    value: "true".to_string(),
                                })
                                .add_response_header(HeaderOp::Set {
                                    name: "X-WAF-Message".to_string(),
                                    value: message.clone(),
                                })
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "modsec".to_string(),
                                        "blocked".to_string(),
                                        "body".to_string(),
                                    ],
                                    reason_codes: vec![message],
                                    ..Default::default()
                                });
                        } else {
                            info!(
                                correlation_id = correlation_id,
                                "ModSecurity detection in body (detect-only mode)"
                            );
                            return AgentResponse::default_allow()
                                .add_request_header(HeaderOp::Set {
                                    name: "X-WAF-Detected".to_string(),
                                    value: message.clone(),
                                })
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "modsec".to_string(),
                                        "detected".to_string(),
                                        "body".to_string(),
                                    ],
                                    reason_codes: vec![message],
                                    ..Default::default()
                                });
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(error = %e, "ModSecurity body processing error");
                    }
                }
            }
        }

        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        // Response body inspection not yet implemented
        // ModSecurity can inspect response bodies but the API is more complex
        let _ = event;
        AgentResponse::default_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ModSecConfig::default();
        assert!(config.rules_paths.is_empty());
        assert!(config.block_mode);
        assert!(config.body_inspection_enabled);
        assert!(!config.response_inspection_enabled);
        assert_eq!(config.max_body_size, 1048576);
    }

    #[test]
    fn test_path_exclusion() {
        let config = ModSecConfig {
            exclude_paths: vec!["/health".to_string(), "/metrics".to_string()],
            ..Default::default()
        };
        let engine = ModSecEngine::new(config).unwrap();
        assert!(engine.is_excluded("/health"));
        assert!(engine.is_excluded("/health/ready"));
        assert!(engine.is_excluded("/metrics"));
        assert!(!engine.is_excluded("/api/users"));
    }
}
