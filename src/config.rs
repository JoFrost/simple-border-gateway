use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct InternalHomeserverConfig {
    pub server_name: String,
    pub federation_domain: String,
    pub target_base_url: String,
}

#[derive(Deserialize, Serialize)]
pub struct ExternalHomeserverConfig {
    pub server_name: String,
    // Should domains be fetched dynamically from well-known files?
    // A bit less secure, but more convenient?
    pub federation_domain: String,
    pub client_domain: String,
    pub verify_keys: BTreeMap<String, String>,
    /// Name of the ruleset to apply for this homeserver.
    pub ruleset: String,
}

#[derive(Deserialize, Serialize)]
pub struct UpstreamProxyAuth {
    pub username: String,
    pub password: String,
}

/// A single filtering rule for an endpoint path/method.
#[derive(Deserialize, Serialize)]
pub struct RuleConfig {
    pub path: String,
    /// HTTP method to match. Omit to match any method.
    pub method: Option<String>,
    /// Defaults to `"CheckSignature"` when absent.
    pub auth_type: Option<String>,
    /// Defaults to `"Federation"` when absent.
    pub endpoint_type: Option<String>,
    /// `"allow"` or `"reject"`. Defaults to `"reject"` when absent.
    pub inbound_action: Option<String>,
    /// `"allow"` or `"reject"`. Defaults to `"reject"` when absent.
    pub outbound_action: Option<String>,
}

/// A named set of rules applied to one or more external homeservers.
#[derive(Deserialize, Serialize)]
pub struct RulesetConfig {
    pub name: String,
    pub rules: Vec<RuleConfig>,
}

#[derive(Deserialize, Serialize)]
pub struct BorderGatewayConfig {
    pub internal_homeservers: Vec<InternalHomeserverConfig>,
    pub external_homeservers: Vec<ExternalHomeserverConfig>,
    pub inbound_proxy: Option<InboundProxyConfig>,
    pub outbound_proxy: Option<OutboundProxyConfig>,
    #[serde(default)]
    pub rulesets: Vec<RulesetConfig>,
}

#[derive(Deserialize, Serialize)]
pub struct InboundProxyConfig {
    #[serde(default = "default_inbound_proxy_listen_address")]
    pub listen_address: String,
    #[serde(default)]
    pub additional_root_certs: Vec<String>,
}

fn default_inbound_proxy_listen_address() -> String {
    "0.0.0.0:8000".to_string()
}

#[derive(Deserialize, Serialize)]
pub struct OutboundProxyConfig {
    #[serde(default = "default_outbound_proxy_listen_address")]
    pub listen_address: String,
    #[serde(default)]
    pub additional_root_certs: Vec<String>,
    pub upstream_proxy_url: Option<String>,

    pub ca_priv_key: String,
    pub ca_cert: String,
    #[serde(default)]
    pub allowed_non_matrix_regexes_dangerous: Vec<String>,
}

fn default_outbound_proxy_listen_address() -> String {
    "0.0.0.0:3128".to_string()
}
