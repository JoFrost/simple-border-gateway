use std::collections::BTreeMap;

use http::{Method, request::Parts};
use log::debug;
use matchit::Router;
use snafu::Snafu;

use crate::{
    config::{EndpointConfig, OverrideRuleConfig},
    matrix::spec::{Action, AuthType, DEFAULT_ENDPOINTS, EndpointType},
};

#[derive(Debug, Snafu)]
pub enum EndpointCompileError {
    #[snafu(display("Invalid endpoint path pattern '{path}'"))]
    InvalidPath {
        path: String,
        source: matchit::InsertError,
    },
    #[snafu(display("Failed to compile endpoint path pattern '{path}'"))]
    RouteConflict {
        path: String,
        source: matchit::InsertError,
    },
    #[snafu(display("Invalid method '{method}' in endpoint '{endpoint}'"))]
    InvalidMethod {
        endpoint: String,
        method: String,
        source: http::method::InvalidMethod,
    },
    #[snafu(display("Endpoint ID '{endpoint}' is declared more than once"))]
    DuplicateEndpointId { endpoint: String },
    #[snafu(display("Non-matrix endpoint '{endpoint}' must declare a domain"))]
    MissingDomain { endpoint: String },
    #[snafu(display("Override rule references unknown endpoint ID '{endpoint}'"))]
    UnknownOverrideEndpoint { endpoint: String },
    #[snafu(display("Endpoint '{endpoint}' has more than one override rule"))]
    DuplicateOverride { endpoint: String },
    #[snafu(display(
        "Unknown {direction}_action '{action}' for endpoint '{endpoint}' (expected 'allow', 'reject', or 'disallow')"
    ))]
    InvalidAction {
        endpoint: String,
        direction: &'static str,
        action: String,
    },
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
pub struct Endpoint {
    pub id: String,
    /// Path pattern matched by the router, using `{name}` placeholders.
    /// A trailing `{*name}` placeholder matches the remaining segments.
    pub path: String,
    pub rule: RuntimeRule,
}

impl Endpoint {
    /// Build a new endpoint with the specified arguments.
    pub fn new(
        id: &str,
        path: &str,
        method: Option<Method>,
        auth_type: AuthType,
        endpoint_type: EndpointType,
        inbound_action: Action,
        outbound_action: Action,
    ) -> Result<Self, EndpointCompileError> {
        validate_path(path)?;
        Ok(Self {
            id: id.to_string(),
            path: path.to_string(),
            rule: RuntimeRule {
                method,
                endpoint_type,
                auth_type,
                inbound_action,
                outbound_action,
            },
        })
    }

    /// Build a new allowed (inbound and outbound) endpoint.
    pub fn new_allowed(
        id: &str,
        path: &str,
        method: Option<Method>,
        auth_type: AuthType,
        endpoint_type: EndpointType,
    ) -> Result<Self, EndpointCompileError> {
        Self::new(
            id,
            path,
            method,
            auth_type,
            endpoint_type,
            Action::Allow,
            Action::Allow,
        )
    }

    /// Build an allowed endpoint using signed federation defaults.
    pub fn new_allowed_signed_fed(
        id: &str,
        path: &str,
        method: Option<Method>,
    ) -> Result<Self, EndpointCompileError> {
        Self::new_allowed(
            id,
            path,
            method,
            AuthType::CheckSignature,
            EndpointType::Federation,
        )
    }
}

/// A set of endpoints compiled into a router for path matching.
/// Several endpoints can share the same path when they match different methods.
#[derive(Clone)]
pub struct EndpointRouter {
    router: Router<Vec<Endpoint>>,
    endpoint_count: usize,
}

impl EndpointRouter {
    pub fn new(endpoints: Vec<Endpoint>) -> Result<Self, EndpointCompileError> {
        let endpoint_count = endpoints.len();
        let mut groups: BTreeMap<String, Vec<Endpoint>> = BTreeMap::new();
        for endpoint in endpoints {
            groups
                .entry(endpoint.path.clone())
                .or_default()
                .push(endpoint);
        }

        let mut router = Router::new();
        for (path, group) in groups {
            router
                .insert(path.clone(), group)
                .map_err(|source| EndpointCompileError::RouteConflict { path, source })?;
        }

        Ok(Self {
            router,
            endpoint_count,
        })
    }

    pub fn empty() -> Self {
        Self {
            router: Router::new(),
            endpoint_count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.endpoint_count
    }

    pub fn is_empty(&self) -> bool {
        self.endpoint_count == 0
    }

    pub fn get(&self, parts: &Parts) -> Option<&Endpoint> {
        let matched = self.router.at(parts.uri.path()).ok()?;
        matched
            .value
            .iter()
            .find(|endpoint| match &endpoint.rule.method {
                Some(expected) => *expected == parts.method,
                None => true,
            })
    }
}

/// A compiled ruleset combining additional endpoint definitions with action overrides.
#[derive(Clone)]
pub struct CompiledRuleset {
    pub additional_endpoints: EndpointRouter,
    pub action_overrides: BTreeMap<String, (Action, Action)>,
}

impl Default for CompiledRuleset {
    fn default() -> Self {
        Self {
            additional_endpoints: EndpointRouter::empty(),
            action_overrides: BTreeMap::new(),
        }
    }
}

pub(crate) struct ResolvedEndpoint<'a> {
    pub(crate) endpoint: &'a Endpoint,
    pub(crate) inbound_action: Action,
    pub(crate) outbound_action: Action,
    pub(crate) is_override: bool,
}

fn validate_path(path: &str) -> Result<(), EndpointCompileError> {
    let mut probe: Router<()> = Router::new();
    probe
        .insert(path, ())
        .map_err(|source| EndpointCompileError::InvalidPath {
            path: path.to_string(),
            source,
        })?;
    Ok(())
}

fn endpoint_from_config(config: &EndpointConfig) -> Result<Endpoint, EndpointCompileError> {
    let method = config
        .method
        .as_deref()
        .map(|method| {
            Method::from_bytes(&method.as_bytes().to_ascii_uppercase()).map_err(|source| {
                EndpointCompileError::InvalidMethod {
                    endpoint: config.id.clone(),
                    method: method.to_string(),
                    source,
                }
            })
        })
        .transpose()?;

    Endpoint::new(
        &config.id,
        &config.path,
        method,
        config.auth_type,
        config.endpoint_type,
        Action::Reject,
        Action::Reject,
    )
}

pub fn build_endpoint_router_from_endpoint_configs(
    endpoints: &[EndpointConfig],
) -> Result<EndpointRouter, EndpointCompileError> {
    let endpoints = endpoints
        .iter()
        .map(endpoint_from_config)
        .collect::<Result<Vec<_>, _>>()?;
    EndpointRouter::new(endpoints)
}

pub fn build_non_matrix_endpoint_routers(
    endpoints: &[EndpointConfig],
) -> Result<BTreeMap<String, EndpointRouter>, EndpointCompileError> {
    let mut routers: BTreeMap<String, Vec<Endpoint>> = BTreeMap::new();
    for config in endpoints {
        let domain =
            config
                .domain
                .as_deref()
                .ok_or_else(|| EndpointCompileError::MissingDomain {
                    endpoint: config.id.clone(),
                })?;
        routers
            .entry(domain.to_ascii_lowercase())
            .or_default()
            .push(endpoint_from_config(config)?);
    }

    routers
        .into_iter()
        .map(|(domain, endpoints)| EndpointRouter::new(endpoints).map(|router| (domain, router)))
        .collect()
}

/// Compile endpoint overrides, rejecting unknown IDs and duplicate rules.
/// Missing directions inherit the endpoint's built-in action.
pub fn compile_override_rules(
    rules: &[OverrideRuleConfig],
    additional_endpoints: &[EndpointConfig],
) -> Result<BTreeMap<String, (Action, Action)>, EndpointCompileError> {
    let mut defaults = BTreeMap::new();
    for endpoint in DEFAULT_ENDPOINTS.iter() {
        if defaults
            .insert(
                endpoint.id.as_str(),
                (endpoint.rule.inbound_action, endpoint.rule.outbound_action),
            )
            .is_some()
        {
            return Err(EndpointCompileError::DuplicateEndpointId {
                endpoint: endpoint.id.clone(),
            });
        }
    }
    for endpoint in additional_endpoints {
        if defaults
            .insert(endpoint.id.as_str(), (Action::Reject, Action::Reject))
            .is_some()
        {
            return Err(EndpointCompileError::DuplicateEndpointId {
                endpoint: endpoint.id.clone(),
            });
        }
    }

    let mut overrides = BTreeMap::new();
    for rule in rules {
        let (default_inbound, default_outbound) = defaults
            .get(rule.endpoint.as_str())
            .copied()
            .ok_or_else(|| EndpointCompileError::UnknownOverrideEndpoint {
                endpoint: rule.endpoint.clone(),
            })?;

        if overrides.contains_key(&rule.endpoint) {
            return Err(EndpointCompileError::DuplicateOverride {
                endpoint: rule.endpoint.clone(),
            });
        }

        let inbound = parse_action(
            rule.inbound_action.as_deref(),
            default_inbound,
            "inbound",
            &rule.endpoint,
        )?;
        let outbound = parse_action(
            rule.outbound_action.as_deref(),
            default_outbound,
            "outbound",
            &rule.endpoint,
        )?;
        overrides.insert(rule.endpoint.clone(), (inbound, outbound));
    }
    Ok(overrides)
}

fn parse_action(
    configured: Option<&str>,
    default: Action,
    direction: &'static str,
    endpoint: &str,
) -> Result<Action, EndpointCompileError> {
    match configured {
        None => Ok(default),
        Some("allow") => Ok(Action::Allow),
        Some("reject" | "disallow") => Ok(Action::Reject),
        Some(action) => Err(EndpointCompileError::InvalidAction {
            endpoint: endpoint.to_string(),
            direction,
            action: action.to_string(),
        }),
    }
}

pub(crate) fn resolve_endpoint<'a>(
    parts: &Parts,
    external_server_name: &str,
    server_rulesets: &'a BTreeMap<String, CompiledRuleset>,
    default_ruleset: &'a EndpointRouter,
) -> Option<ResolvedEndpoint<'a>> {
    let ruleset = server_rulesets.get(external_server_name);

    debug!(
        "Ruleset lookup for external server '{external_server_name}': found ruleset: {}, additional endpoints: {}",
        ruleset.is_some(),
        ruleset.map_or(0, |ruleset| ruleset.additional_endpoints.len())
    );

    let (endpoint, is_from_additional) =
        match ruleset.and_then(|ruleset| ruleset.additional_endpoints.get(parts)) {
            Some(endpoint) => (endpoint, true),
            None => (default_ruleset.get(parts)?, false),
        };

    let action_override = ruleset
        .and_then(|ruleset| ruleset.action_overrides.get(&endpoint.id))
        .copied();
    let (inbound_action, outbound_action) =
        action_override.unwrap_or((endpoint.rule.inbound_action, endpoint.rule.outbound_action));
    let is_override = is_from_additional || action_override.is_some();

    debug!(
        "Matched endpoint: {}, is_from_additional: {is_from_additional}, has_override: {}, inbound_action: {inbound_action:?}, outbound_action: {outbound_action:?}",
        endpoint.id,
        action_override.is_some()
    );

    Some(ResolvedEndpoint {
        endpoint,
        inbound_action,
        outbound_action,
        is_override,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_override_direction_inherits_endpoint_default() {
        let overrides = compile_override_rules(
            &[OverrideRuleConfig {
                endpoint: "query_profile".to_string(),
                inbound_action: None,
                outbound_action: Some("reject".to_string()),
            }],
            &[],
        )
        .expect("override should compile");

        assert_eq!(
            overrides.get("query_profile"),
            Some(&(Action::Allow, Action::Reject))
        );
    }

    #[test]
    fn unknown_and_duplicate_overrides_are_rejected() {
        let unknown = compile_override_rules(
            &[OverrideRuleConfig {
                endpoint: "inbound_acton".to_string(),
                inbound_action: Some("allow".to_string()),
                outbound_action: None,
            }],
            &[],
        );
        assert!(matches!(
            unknown,
            Err(EndpointCompileError::UnknownOverrideEndpoint { .. })
        ));

        let duplicate_rule = OverrideRuleConfig {
            endpoint: "query_profile".to_string(),
            inbound_action: Some("allow".to_string()),
            outbound_action: None,
        };
        let duplicate = compile_override_rules(&[duplicate_rule.clone(), duplicate_rule], &[]);
        assert!(matches!(
            duplicate,
            Err(EndpointCompileError::DuplicateOverride { .. })
        ));
    }

    #[test]
    fn additional_endpoint_missing_direction_remains_rejected() {
        let additional = EndpointConfig {
            id: "custom".to_string(),
            path: "/custom".to_string(),
            method: None,
            auth_type: AuthType::CheckSignature,
            endpoint_type: EndpointType::Federation,
            domain: None,
        };
        let overrides = compile_override_rules(
            &[OverrideRuleConfig {
                endpoint: "custom".to_string(),
                inbound_action: Some("allow".to_string()),
                outbound_action: None,
            }],
            &[additional],
        )
        .expect("override should compile");

        assert_eq!(
            overrides.get("custom"),
            Some(&(Action::Allow, Action::Reject))
        );
    }
}
