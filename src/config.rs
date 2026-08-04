use std::collections::BTreeMap;

use serde::{de, Deserialize, Deserializer, Serialize};
use url::Url;

// Lowercase at import time the requested string.
// This will enforce domains to be lowercase...
fn deserialize_lowercase<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value: String = String::deserialize(deserializer)?;
    Ok(value.to_ascii_lowercase())
}

// Special deserializer for base URLs, which will ensure that the URL is valid and normalized
fn deserialize_base_url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let url = Url::parse(&value).map_err(de::Error::custom)?;
    Ok(url.to_string())
}

#[derive(Deserialize, Serialize)]
pub struct InternalHomeserverConfig {
    #[serde(deserialize_with = "deserialize_lowercase")]
    pub server_name: String,
    #[serde(deserialize_with = "deserialize_lowercase")]
    pub federation_domain: String,
    #[serde(deserialize_with = "deserialize_base_url")]
    pub target_base_url: String,
}

#[derive(Deserialize, Serialize)]
pub struct ExternalHomeserverConfig {
    #[serde(deserialize_with = "deserialize_lowercase")]
    pub server_name: String,
    // Should domains be fetched dynamically from well-known files?
    // A bit less secure, but more convenient?
    #[serde(deserialize_with = "deserialize_lowercase")]
    pub federation_domain: String,
    #[serde(deserialize_with = "deserialize_lowercase")]
    pub client_domain: String,
    pub verify_keys: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
pub struct UpstreamProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Serialize)]
pub struct BorderGatewayConfig {
    pub internal_homeservers: Vec<InternalHomeserverConfig>,
    pub external_homeservers: Vec<ExternalHomeserverConfig>,
    pub inbound_proxy: Option<InboundProxyConfig>,
    pub outbound_proxy: Option<OutboundProxyConfig>,
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
