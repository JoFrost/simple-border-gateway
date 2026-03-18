use std::collections::BTreeMap;
use std::net::SocketAddr;

use bytes::Bytes;
use http::{request::Parts, uri::Scheme, Method};
use http_body_util::{BodyExt, Limited};
use log::{log, Level};
use regex::Regex;
use reqwest::Body;
use snafu::{ResultExt as _, Whatever};

use crate::{
    config::EndpointConfig,
    http_gateway::{
        util::{extract_destination_host, extract_origin_ip},
        GatewayDirection,
    },
    matrix::{
        spec::{Action, AuthType, EndpointType},
        util::NameResolver,
    },
};

// ring and aws_lc_rs are mutually exclusive.
#[cfg(all(feature = "aws_lc_rs", feature = "ring"))]
compile_error!("features `aws_lc_rs` and `ring` cannot be enabled at the same time");

#[cfg(feature = "aws_lc_rs")]
pub use rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use rustls::crypto::ring as crypto_provider;

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}

/// Runtime representation of a filtering rule that owns its path string.
#[derive(Clone, Debug)]
pub struct RuntimeRule {
    pub method: Option<Method>,
    pub endpoint_type: EndpointType,
    pub auth_type: AuthType,
    pub inbound_action: Action,
    pub outbound_action: Action,
}

#[derive(Clone, Debug)]
pub struct RegexEndpoint {
    pub id: String,
    regex: Regex,
    pub rule: RuntimeRule,
}

impl RegexEndpoint {
    /// Build a RegexEndpoint directly from typed values (used by the default ruleset).
    pub fn new(
        id: &str,
        path: &str,
        method: Option<Method>,
        auth_type: AuthType,
        endpoint_type: EndpointType,
        inbound_action: Action,
        outbound_action: Action,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            id: id.to_string(),
            regex: path_to_regex(path)?,
            rule: RuntimeRule {
                method,
                endpoint_type,
                auth_type,
                inbound_action,
                outbound_action,
            },
        })
    }
}

/// A compiled ruleset combining additional endpoint definitions with action overrides.
#[derive(Clone)]
pub struct CompiledRuleset {
    pub additional_endpoints: Vec<RegexEndpoint>,
    pub action_overrides: BTreeMap<String, (Action, Action)>,
}

#[allow(clippy::unwrap_used, reason = "lazy static regex")]
static REPLACE_VARIABLES_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new("\\{[^\\}]*}").unwrap());

fn path_to_regex(path: &str) -> Result<Regex, regex::Error> {
    let escaped = path.replace('.', "\\.");
    let pattern = REPLACE_VARIABLES_RE.replace_all(&escaped, ".*");
    Regex::new(&pattern)
}

/// Convert additional endpoint configs into RegexEndpoints.
/// Actions default to Reject/Reject since they are expected to be set via override_rules.
pub fn build_regex_endpoints_from_endpoint_configs(
    endpoints: &[EndpointConfig],
) -> Result<Vec<RegexEndpoint>, Whatever> {
    endpoints
        .iter()
        .map(|e| {
            let method = e
                .method
                .as_deref()
                .map(|m| {
                    Method::from_bytes(m.as_bytes())
                        .whatever_context(format!("Invalid method '{}' in endpoint '{}'", m, e.id))
                })
                .transpose()?;

            let auth_type = match e.auth_type.as_deref() {
                None | Some("CheckSignature") => AuthType::CheckSignature,
                Some("Unauthenticated") => AuthType::Unauthenticated,
                Some(other) => {
                    snafu::whatever!("Unknown auth_type '{}' in endpoint '{}'", other, e.id)
                }
            };

            let endpoint_type = match e.endpoint_type.as_deref() {
                None | Some("Federation") => EndpointType::Federation,
                Some("WellKnown") => EndpointType::WellKnown,
                Some("LegacyMedia") => EndpointType::LegacyMedia,
                Some(other) => {
                    snafu::whatever!("Unknown endpoint_type '{}' in endpoint '{}'", other, e.id)
                }
            };

            let regex = path_to_regex(&e.path).whatever_context(format!(
                "Invalid path pattern '{}' in endpoint '{}'",
                e.path, e.id
            ))?;

            Ok(RegexEndpoint {
                id: e.id.clone(),
                regex,
                rule: RuntimeRule {
                    method,
                    endpoint_type,
                    auth_type,
                    inbound_action: Action::Reject,
                    outbound_action: Action::Reject,
                },
            })
        })
        .collect()
}

/// Compile override rules into a map of endpoint ID → (inbound_action, outbound_action).
pub fn compile_override_rules(
    rules: &[crate::config::OverrideRuleConfig],
) -> Result<BTreeMap<String, (Action, Action)>, Whatever> {
    let mut map = BTreeMap::new();
    for r in rules {
        let inbound_action = match r.inbound_action.as_deref() {
            None | Some("reject") | Some("disallow") => Action::Reject,
            Some("allow") => Action::Allow,
            Some(other) => snafu::whatever!(
                "Unknown inbound_action '{}' for endpoint '{}' (expected 'allow' or 'reject')",
                other,
                r.endpoint
            ),
        };

        let outbound_action = match r.outbound_action.as_deref() {
            None | Some("reject") | Some("disallow") => Action::Reject,
            Some("allow") => Action::Allow,
            Some(other) => snafu::whatever!(
                "Unknown outbound_action '{}' for endpoint '{}' (expected 'allow' or 'reject')",
                other,
                r.endpoint
            ),
        };

        map.insert(r.endpoint.clone(), (inbound_action, outbound_action));
    }
    Ok(map)
}

pub(crate) fn get_matching_endpoint<'a>(
    parts: &Parts,
    allowed_endpoints: &'a [RegexEndpoint],
) -> Option<&'a RegexEndpoint> {
    for endpoint in allowed_endpoints {
        if endpoint.regex.is_match(parts.uri.to_string().as_str()) {
            if let Some(expected_method) = &endpoint.rule.method {
                if expected_method == parts.method {
                    return Some(endpoint);
                }
            } else {
                return Some(endpoint);
            }
        }
    }
    None
}

pub(crate) async fn to_bytes(body: Body, limit: usize) -> Option<Bytes> {
    Limited::new(body, limit)
        .collect()
        .await
        .map(|col| col.to_bytes())
        .ok()
}

pub(crate) struct RequestContext {
    pub(crate) parts: Parts,
    pub(crate) origin_server_name: String,
    pub(crate) destination_server_name: String,
    pub(crate) destination_host: String,
    log_prefix: String,
}

impl RequestContext {
    pub(crate) fn new(
        parts: Parts,
        direction: GatewayDirection,
        client_addr: SocketAddr,
        name_resolver: &mut NameResolver,
    ) -> Self {
        let origin_ip = extract_origin_ip(&parts, &direction, &client_addr);
        let destination_host = extract_destination_host(&parts, &direction).to_string();
        Self {
            parts,
            origin_server_name: name_resolver.ip_to_server_name(&origin_ip),
            destination_server_name: name_resolver.domain_to_server_name(&destination_host),
            destination_host,
            log_prefix: match direction {
                GatewayDirection::Inbound => "IN ",
                GatewayDirection::Outbound => "OUT",
            }
            .to_string(),
        }
    }

    pub(crate) fn log(&self, level: Level, msg: &str) {
        log!(
            level,
            "{0}: {1} -> {2} {3} {4} : {5}",
            self.log_prefix,
            self.origin_server_name,
            self.destination_server_name,
            self.parts.method,
            self.parts.uri.path_and_query().map_or("", |p| p.as_str()),
            msg,
        );
    }
}

#[allow(
    clippy::unwrap_used,
    reason = "we only remove default ports from a validated uri so no new untrusted input"
)]
pub(crate) fn remove_default_ports_from_uri(uri: http::Uri) -> String {
    let mut parts = uri.into_parts();
    if let Some(authority) = parts.authority.clone() {
        let host = authority.host().to_string();
        if let Some(port) = authority.port_u16() {
            if port == 443 && parts.scheme == Some(Scheme::HTTPS)
                || port == 80 && parts.scheme == Some(Scheme::HTTP)
            {
                parts.authority = Some(http::uri::Authority::from_maybe_shared(host).unwrap());
            }
        }
    }
    http::Uri::from_parts(parts).unwrap().to_string()
}

pub fn read_pem(path_or_content: &str) -> Result<String, Whatever> {
    let bytes = if path_or_content.starts_with("----") {
        path_or_content.as_bytes().to_vec()
    } else {
        std::fs::read(path_or_content).whatever_context("Failed to read PEM file")?
    };
    String::from_utf8(bytes).whatever_context("Failed to convert PEM content to UTF-8")
}

pub fn create_http_client(
    additional_root_certs: Vec<String>,
    upstream_proxy_url: Option<String>,
) -> Result<reqwest::Client, Whatever> {
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(upstream_proxy_url) = upstream_proxy_url {
        builder = builder.proxy(
            reqwest::Proxy::all(upstream_proxy_url)
                .whatever_context("Failed to create reqwest proxy config")?,
        );
    }
    for cert in additional_root_certs {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(
                read_pem(&cert)
                    .whatever_context("Failed to read PEM")?
                    .as_bytes(),
            )
            .whatever_context("Failed to parse PEM")?,
        );
    }
    // dns resolver dns overrides ?
    builder
        .build()
        .whatever_context("Failed to build reqwest client")
}
