use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, de};
use snafu::Snafu;
use url::Url;

use crate::matrix::spec::{AuthType, EndpointType};

#[derive(Debug, Snafu)]
pub enum ConfigError {
    #[snafu(display("Failed to read config file {}", path.display()))]
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to deserialize config file {}", path.display()))]
    DeserializeConfig {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[snafu(display("Invalid ruleset name '{name}': {reason}"))]
    InvalidRulesetName { name: String, reason: &'static str },
    #[snafu(display("Ruleset '{name}' is defined more than once"))]
    DuplicateRuleset { name: String },
    #[snafu(display("Failed to read ruleset file {}", path.display()))]
    ReadRuleset {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to deserialize ruleset file {}", path.display()))]
    DeserializeRuleset {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[snafu(display(
        "Ruleset file {} declares name '{declared}', but it was referenced as '{referenced}'",
        path.display()
    ))]
    RulesetNameMismatch {
        path: PathBuf,
        declared: String,
        referenced: String,
    },
}

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
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InternalHomeserverConfig {
    #[serde(deserialize_with = "deserialize_lowercase")]
    pub server_name: String,
    #[serde(deserialize_with = "deserialize_lowercase")]
    pub federation_domain: String,
    #[serde(deserialize_with = "deserialize_base_url")]
    pub target_base_url: String,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
    /// Name of the ruleset to apply for this homeserver.
    /// If omitted, the default ruleset is used.
    pub ruleset: Option<String>,
}

/// An endpoint definition with a unique ID, path pattern, and optional domain/method/auth/type constraints.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub id: String,
    /// Path pattern to match. `{name}` matches a single path segment, while a
    /// trailing `{*name}` matches all remaining segments.
    pub path: String,
    /// HTTP method to match. Omit to match any method.
    pub method: Option<String>,
    /// Defaults to `"CheckSignature"` when absent.
    #[serde(default)]
    pub auth_type: AuthType,
    /// Defaults to `"Federation"` when absent.
    #[serde(default)]
    pub endpoint_type: EndpointType,
    /// Optional destination host this endpoint is restricted to.
    /// Required for endpoints declared under `outbound_proxy.hazmat_non_matrix_endpoints`,
    /// ignored in ruleset `additional_endpoints` (which are already scoped to a server).
    #[serde(default)]
    pub domain: Option<String>,
}

/// An override rule that references an endpoint by ID and specifies actions.
/// The endpoint can be a default endpoint or an additional endpoint.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideRuleConfig {
    /// ID of the endpoint to override (from the default ruleset or an additional endpoint).
    pub endpoint: String,
    /// `"allow"`, `"disallow"` or `"reject"`. Inherits the endpoint default when absent.
    pub inbound_action: Option<String>,
    /// `"allow"`, `"disallow"` or `"reject"`. Inherits the endpoint default when absent.
    pub outbound_action: Option<String>,
}

/// A named set of override rules applied to one or more external homeservers.
/// Override rules take precedence over the default ruleset.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetConfig {
    /// Required for rulesets declared inline in the main configuration. External ruleset files
    /// inherit their name from the filename and may omit this field.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub additional_endpoints: Vec<EndpointConfig>,
    #[serde(default)]
    pub override_rules: Vec<OverrideRuleConfig>,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BorderGatewayConfig {
    pub internal_homeservers: Vec<InternalHomeserverConfig>,
    pub external_homeservers: Vec<ExternalHomeserverConfig>,
    pub inbound_proxy: Option<InboundProxyConfig>,
    pub outbound_proxy: Option<OutboundProxyConfig>,
    #[serde(default)]
    pub rulesets: Vec<RulesetConfig>,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboundProxyConfig {
    #[serde(default = "default_inbound_proxy_listen_address")]
    pub listen_address: String,
    #[serde(default)]
    pub additional_root_certs: Vec<String>,
}

fn default_inbound_proxy_listen_address() -> String {
    "0.0.0.0:8000".to_string()
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundProxyConfig {
    #[serde(default = "default_outbound_proxy_listen_address")]
    pub listen_address: String,
    #[serde(default)]
    pub additional_root_certs: Vec<String>,
    #[serde(default)]
    pub upstream_proxy: Option<UpstreamProxyConfig>,

    pub ca_priv_key: String,
    pub ca_cert: String,
    /// Endpoints allowed on specific external (non-Matrix) domains, in addition to the
    /// federation traffic. Each endpoint must set `domain`; requests are forwarded when
    /// both the destination host and the endpoint path (and method, if set) match.
    #[serde(default)]
    pub hazmat_non_matrix_endpoints: Vec<EndpointConfig>,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProxyConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

fn default_outbound_proxy_listen_address() -> String {
    "0.0.0.0:3128".to_string()
}

impl BorderGatewayConfig {
    /// Load the main configuration and every externally referenced ruleset.
    pub fn load(config_file: &Path) -> Result<Self, ConfigError> {
        let config_toml =
            fs::read_to_string(config_file).map_err(|source| ConfigError::ReadConfig {
                path: config_file.to_path_buf(),
                source,
            })?;
        let mut config: Self =
            toml::from_str(&config_toml).map_err(|source| ConfigError::DeserializeConfig {
                path: config_file.to_path_buf(),
                source,
            })?;

        let config_dir = config_file.parent().unwrap_or_else(|| Path::new("."));
        config.load_external_rulesets(config_dir)?;
        config.resolve_pem_paths(config_dir);
        Ok(config)
    }

    /// Load referenced rulesets that are not defined inline. External rulesets live in a
    /// `ruleset_name.toml` side file beside the main configuration.
    fn load_external_rulesets(&mut self, config_dir: &Path) -> Result<(), ConfigError> {
        let mut inline_names = BTreeSet::new();
        for ruleset in &self.rulesets {
            validate_ruleset_name(&ruleset.name)?;
            if !inline_names.insert(ruleset.name.clone()) {
                return Err(ConfigError::DuplicateRuleset {
                    name: ruleset.name.clone(),
                });
            }
        }

        let mut ruleset_names = BTreeSet::new();
        for homeserver in &self.external_homeservers {
            if let Some(ref name) = homeserver.ruleset {
                validate_ruleset_name(name)?;
                ruleset_names.insert(name.clone());
            }
        }

        for ruleset_name in ruleset_names {
            if inline_names.contains(&ruleset_name) {
                continue;
            }

            let ruleset_path = config_dir.join(format!("{}.toml", ruleset_name));
            let ruleset_content =
                fs::read_to_string(&ruleset_path).map_err(|source| ConfigError::ReadRuleset {
                    path: ruleset_path.clone(),
                    source,
                })?;
            let mut ruleset: RulesetConfig =
                toml::from_str(&ruleset_content).map_err(|source| {
                    ConfigError::DeserializeRuleset {
                        path: ruleset_path.clone(),
                        source,
                    }
                })?;

            if !ruleset.name.is_empty() && ruleset.name != ruleset_name {
                return Err(ConfigError::RulesetNameMismatch {
                    path: ruleset_path,
                    declared: ruleset.name,
                    referenced: ruleset_name,
                });
            }
            ruleset.name = ruleset_name.clone();
            inline_names.insert(ruleset_name);
            self.rulesets.push(ruleset);
        }

        Ok(())
    }

    fn resolve_pem_paths(&mut self, config_dir: &Path) {
        if let Some(inbound) = &mut self.inbound_proxy {
            resolve_pem_path_list(&mut inbound.additional_root_certs, config_dir);
        }
        if let Some(outbound) = &mut self.outbound_proxy {
            resolve_pem_path(&mut outbound.ca_priv_key, config_dir);
            resolve_pem_path(&mut outbound.ca_cert, config_dir);
            resolve_pem_path_list(&mut outbound.additional_root_certs, config_dir);
        }
    }
}

fn validate_ruleset_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::InvalidRulesetName {
            name: name.to_string(),
            reason: "the name cannot be empty",
        });
    }
    if name.contains('\\') {
        return Err(ConfigError::InvalidRulesetName {
            name: name.to_string(),
            reason: "path separators are not allowed",
        });
    }

    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(ConfigError::InvalidRulesetName {
            name: name.to_string(),
            reason: "the name must be a single path component",
        });
    }
    Ok(())
}

fn resolve_pem_path_list(values: &mut [String], config_dir: &Path) {
    for value in values {
        resolve_pem_path(value, config_dir);
    }
}

fn resolve_pem_path(value: &mut String, config_dir: &Path) {
    if value.trim_start().starts_with("-----BEGIN ") || Path::new(value).is_absolute() {
        return;
    }
    *value = config_dir.join(&*value).to_string_lossy().into_owned();
}
