use crate::{
    config::RuleConfig,
    util::{build_regex_endpoints_from_config, RegexEndpoint},
};
use once_cell::sync::Lazy;

#[derive(Clone, PartialEq)]
pub(crate) enum EndpointType {
    Federation,
    WellKnown,
    LegacyMedia,
}

#[derive(Clone, PartialEq)]
pub(crate) enum AuthType {
    Unauthenticated,
    CheckSignature,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Action {
    Allow,
    Reject,
}

// Those endpoints are authorized by default, and are not subject to the rules defined in the configuration file.
// Had to be defined as static unfortunately, as the struct takes Strings...

// The /_matrix/key/v2/query, /_matrix/key/v2/query/{server_name} and /_matrix/media/{path}
// are not part of this listing on purpose, as they may leaks data.
pub(crate) static WHITELISTED_ENDPOINTS: Lazy<Vec<RegexEndpoint>> = Lazy::new(|| {
    let rules = vec![
        // 2.1 Resolving server names
        RuleConfig {
            path: "/.well-known/matrix/server".to_string(),
            method: Some("GET".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("WellKnown".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 2.2 Server implementation
        RuleConfig {
            path: "/_matrix/federation/v1/version".to_string(),
            method: Some("GET".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("WellKnown".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 2.3 Retrieving server keys
        RuleConfig {
            path: "/_matrix/key/v2/server".to_string(),
            method: Some("GET".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("WellKnown".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
    ];
    build_regex_endpoints_from_config(&rules).expect("Invalid hardcoded whitelisted endpoint(s)")
});
