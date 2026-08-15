use mcpg_plugin_protocol::{GateDecision, PluginContext, PluginIdentity};
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde_json::json;

use super::SchemaGatePlugin;

fn ctx() -> PluginContext {
    PluginContext {
        request_id: "t".into(),
        session_id: None,
        tool_name: "x".into(),
        surface: "tool".into(),
        identity: PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "unauthenticated".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: Default::default(),
        },
        transport: "http".into(),
    }
}

/// Evaluate `arguments` against a gate built from `cfg`.
fn eval(cfg: serde_json::Value, arguments: serde_json::Value) -> GateDecision {
    let p = SchemaGatePlugin::from_config_json(&cfg.to_string());
    p.evaluate_pre(&ctx(), &arguments, None, &json!({}))
}

fn deny_of(d: GateDecision) -> (u16, i32, String) {
    match d {
        GateDecision::Deny {
            http_status,
            code,
            message,
            ..
        } => (http_status, code, message),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn valid_arguments_allow() {
    let d = eval(
        json!({ "schema": { "type": "object", "required": ["query"] } }),
        json!({ "query": "hello" }),
    );
    assert!(matches!(d, GateDecision::Allow { .. }));
}

#[test]
fn missing_required_field_denies_with_invalid_params() {
    let d = eval(
        json!({ "schema": { "type": "object", "required": ["query"] } }),
        json!({}),
    );
    let (status, code, msg) = deny_of(d);
    assert_eq!(status, 400);
    assert_eq!(code, -32602);
    assert!(msg.contains("query") || msg.contains("required"), "{msg}");
}

#[test]
fn constraint_violation_denies() {
    let d = eval(
        json!({ "schema": { "type": "object", "properties": { "limit": { "type": "integer", "maximum": 100 } } } }),
        json!({ "limit": 250 }),
    );
    let (_, _, msg) = deny_of(d);
    assert!(msg.contains("argument schema validation failed"), "{msg}");
}

#[test]
fn custom_code_and_status_are_honoured() {
    let d = eval(
        json!({ "schema": { "type": "string" }, "code": -32000, "http_status": 422 }),
        json!(42),
    );
    let (status, code, _) = deny_of(d);
    assert_eq!(status, 422);
    assert_eq!(code, -32000);
}

#[test]
fn fixed_deny_message_hides_schema_details() {
    let d = eval(
        json!({ "schema": { "type": "object", "required": ["secret_field"] }, "deny_message": "Bad request" }),
        json!({}),
    );
    let (_, _, msg) = deny_of(d);
    assert_eq!(msg, "Bad request");
    assert!(
        !msg.contains("secret_field"),
        "must not echo schema internals: {msg}"
    );
}

#[test]
fn pointer_validates_subfield() {
    let cfg = json!({ "schema": { "type": "array" }, "pointer": "/items" });
    assert!(matches!(
        eval(cfg.clone(), json!({ "items": [1, 2], "page": 1 })),
        GateDecision::Allow { .. }
    ));
    assert!(matches!(
        eval(cfg, json!({ "items": "nope" })),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn missing_pointer_target_denies() {
    let d = eval(
        json!({ "schema": { "type": "array" }, "pointer": "/missing" }),
        json!({}),
    );
    let (_, _, msg) = deny_of(d);
    assert!(msg.contains("not found"), "{msg}");
}

#[test]
fn max_errors_caps_detail() {
    let d = eval(
        json!({ "schema": { "type": "object", "required": ["a", "b", "c", "d"] }, "max_errors": 1 }),
        json!({}),
    );
    let (_, _, msg) = deny_of(d);
    assert!(msg.contains("more than 1 errors"), "{msg}");
}

#[test]
fn post_dispatch_always_allows() {
    let p =
        SchemaGatePlugin::from_config_json(&json!({ "schema": { "type": "string" } }).to_string());
    assert!(matches!(
        p.evaluate_post(&ctx(), &json!(42), &json!(42), 1, &json!({})),
        GateDecision::Allow { .. }
    ));
}

#[test]
#[should_panic(expected = "invalid JSON Schema")]
fn bad_schema_fails_closed_at_load() {
    // `type: 123` is not a valid schema → refuse to instantiate (fail closed).
    SchemaGatePlugin::from_config_json(&json!({ "schema": { "type": 123 } }).to_string());
}

#[test]
#[should_panic(expected = "config JSON failed to parse")]
fn unknown_config_field_fails_closed_at_load() {
    SchemaGatePlugin::from_config_json(
        &json!({ "schema": { "type": "string" }, "bogus": 1 }).to_string(),
    );
}
