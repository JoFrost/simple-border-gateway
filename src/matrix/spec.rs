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

// Built-in default ruleset containing all standard Matrix federation endpoints.
// Override rules from external TOML files take precedence over these defaults.
pub(crate) static DEFAULT_RULESET: Lazy<Vec<RegexEndpoint>> = Lazy::new(|| {
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
        RuleConfig {
            path: "/_matrix/key/v2/query".to_string(),
            method: Some("POST".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/key/v2/query/{server_name}".to_string(),
            method: Some("GET".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 4. Transactions
        RuleConfig {
            path: "/_matrix/federation/v1/send/{txnId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 5.1.5 Retrieving event authorization information
        RuleConfig {
            path: "/_matrix/federation/v1/event_auth/{roomId}/{eventId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 8. Backfilling and retrieving missing events
        RuleConfig {
            path: "/_matrix/federation/v1/backfill/{roomId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/get_missing_events/{roomId}".to_string(),
            method: Some("POST".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 9. Retrieving events
        RuleConfig {
            path: "/_matrix/federation/v1/event/{eventId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/state/{roomId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/state_ids/{roomId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/timestamp_to_event/{roomId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 10. Joining rooms
        RuleConfig {
            path: "/_matrix/federation/v1/make_join/{roomId}/{userId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/send_join/{roomId}/{eventId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v2/send_join/{roomId}/{eventId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 11. Knocking
        RuleConfig {
            path: "/_matrix/federation/v1/make_knock/{roomId}/{userId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/send_knock/{roomId}/{eventId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 12. Inviting
        RuleConfig {
            path: "/_matrix/federation/v1/invite/{roomId}/{eventId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v2/invite/{roomId}/{eventId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 13. Leaving rooms
        RuleConfig {
            path: "/_matrix/federation/v1/make_leave/{roomId}/{userId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/send_leave/{roomId}/{eventId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v2/send_leave/{roomId}/{eventId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 14. Third-party invites
        RuleConfig {
            path: "/_matrix/federation/v1/3pid/onbind".to_string(),
            method: Some("PUT".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/exchange_third_party_invite/{roomId}".to_string(),
            method: Some("PUT".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 15. Public room directory
        RuleConfig {
            path: "/_matrix/federation/v1/publicRooms".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/publicRooms".to_string(),
            method: Some("POST".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 16. Spaces
        RuleConfig {
            path: "/_matrix/federation/v1/hierarchy/{roomId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 20. Querying for information
        RuleConfig {
            path: "/_matrix/federation/v1/query/directory".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/query/profile".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/query/{queryType}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 21. OpenID
        RuleConfig {
            path: "/_matrix/federation/v1/openid/userinfo".to_string(),
            method: Some("GET".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 22. Device management
        RuleConfig {
            path: "/_matrix/federation/v1/user/devices/{userId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 23. End-to-end encryption
        RuleConfig {
            path: "/_matrix/federation/v1/user/keys/claim".to_string(),
            method: Some("POST".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/user/keys/query".to_string(),
            method: Some("POST".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 25. Content repository
        RuleConfig {
            path: "/_matrix/federation/v1/media/download/{mediaId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        RuleConfig {
            path: "/_matrix/federation/v1/media/thumbnail/{mediaId}".to_string(),
            method: Some("GET".to_string()),
            auth_type: None,
            endpoint_type: Some("Federation".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // 25bis. Legacy content repository (any method)
        RuleConfig {
            path: "/_matrix/media/{path}".to_string(),
            method: None,
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("LegacyMedia".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
        // Needed for legacy content repository discovery
        RuleConfig {
            path: "/.well-known/matrix/client".to_string(),
            method: Some("GET".to_string()),
            auth_type: Some("Unauthenticated".to_string()),
            endpoint_type: Some("WellKnown".to_string()),
            inbound_action: Some("allow".to_string()),
            outbound_action: Some("allow".to_string()),
        },
    ];
    build_regex_endpoints_from_config(&rules)
        .expect("Invalid hardcoded default ruleset endpoint(s)")
});
