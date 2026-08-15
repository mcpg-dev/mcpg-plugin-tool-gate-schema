//! JSON Schema contract ToolGate plugin.
//!
//! Validates tool-call arguments against an operator-supplied inline JSON
//! Schema and rejects malformed calls with a precise 4xx before dispatch. The
//! schema is compiled ONCE at load (the operator config is parsed in
//! `from_config_json`, the tool-gate convention — the per-call `config` slot
//! carries request context, not the operator config). Validation is pure CPU,
//! fully offline (in-document `$ref` only). Fails closed on bad config.

use mcpg_plugin_protocol::{GateDecision, PluginContext, PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_MAX_ERRORS: usize = 32;
/// JSON-RPC "Invalid params".
const DEFAULT_CODE: i32 = -32602;
const DEFAULT_HTTP_STATUS: u16 = 400;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaGateConfig {
    /// The inline JSON Schema arguments must satisfy (in-document `$ref` only).
    schema: Value,
    /// JSON Pointer (RFC 6901) to the arguments sub-value to validate. When
    /// omitted (or `""`), the whole arguments object is validated.
    #[serde(default)]
    pointer: Option<String>,
    /// Cap on the number of validation errors surfaced in the deny message.
    #[serde(default = "default_max_errors")]
    max_errors: usize,
    /// JSON-RPC error code for the deny (default -32602 Invalid params).
    #[serde(default = "default_code")]
    code: i32,
    /// HTTP status for the deny (default 400).
    #[serde(default = "default_http_status")]
    http_status: u16,
    /// Optional fixed deny message. When set, the schema error details are NOT
    /// echoed to the caller (use when the contract itself is sensitive).
    #[serde(default)]
    deny_message: Option<String>,
}

fn default_max_errors() -> usize {
    DEFAULT_MAX_ERRORS
}
fn default_code() -> i32 {
    DEFAULT_CODE
}
fn default_http_status() -> u16 {
    DEFAULT_HTTP_STATUS
}

pub struct SchemaGatePlugin {
    manifest: PluginManifest,
    validator: jsonschema::Validator,
    pointer: Option<String>,
    max_errors: usize,
    code: i32,
    http_status: u16,
    deny_message: Option<String>,
}

impl SchemaGatePlugin {
    /// SDK factory: parse operator config. A security control FAILS CLOSED on
    /// bad config by refusing to instantiate (panic → null handle → boot Err),
    /// the uniform tool-gate convention (see ip-allowlist).
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg: SchemaGateConfig = serde_json::from_str(config_json)
            .unwrap_or_else(|err| panic!("tool-gate-schema: config JSON failed to parse: {err}"));
        let validator = jsonschema::validator_for(&cfg.schema)
            .unwrap_or_else(|err| panic!("tool-gate-schema: invalid JSON Schema: {err}"));
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.tool-gate.schema",
                name: "JSON Schema Contract Gate",
                class: ToolGate,
            },
            validator,
            pointer: cfg.pointer,
            max_errors: cfg.max_errors,
            code: cfg.code,
            http_status: cfg.http_status,
            deny_message: cfg.deny_message,
        }
    }

    fn deny(&self, detail: String) -> GateDecision {
        let message = match &self.deny_message {
            Some(m) => m.clone(),
            None => format!("argument schema validation failed: {detail}"),
        };
        GateDecision::Deny {
            http_status: self.http_status,
            code: self.code,
            message,
            error_data: None,
        }
    }
}

impl SyncToolGate for SchemaGatePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        _ctx: &PluginContext,
        arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        let ptr = self.pointer.as_deref().unwrap_or("");
        let target = match arguments.pointer(ptr) {
            Some(t) => t,
            None => return self.deny(format!("arguments pointer {ptr:?} not found")),
        };

        let mut messages: Vec<String> = Vec::new();
        let mut truncated = false;
        for (i, err) in self.validator.iter_errors(target).enumerate() {
            if i >= self.max_errors {
                truncated = true;
                break;
            }
            if err.instance_path.as_str().is_empty() {
                messages.push(err.to_string());
            } else {
                messages.push(format!("{}: {}", err.instance_path, err));
            }
        }

        if messages.is_empty() {
            GateDecision::allow()
        } else {
            let mut detail = messages.join("; ");
            if truncated {
                detail.push_str(&format!(" (… more than {} errors)", self.max_errors));
            }
            self.deny(detail)
        }
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &Value,
        _result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        // Pre-dispatch contract gate; nothing to enforce post-dispatch.
        GateDecision::allow()
    }
}

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.tool-gate.schema",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: SchemaGatePlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| SchemaGatePlugin::from_config_json(cfg),
        },
    ],
}

#[cfg(test)]
mod tests;
