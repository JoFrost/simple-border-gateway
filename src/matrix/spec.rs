use crate::util::RegexEndpoint;
use http::Method;
use once_cell::sync::Lazy;

#[derive(Clone, PartialEq, Debug)]
pub enum EndpointType {
    Federation,
    WellKnown,
    LegacyMedia,
}

#[derive(Clone, PartialEq, Debug)]
pub enum AuthType {
    Unauthenticated,
    CheckSignature,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Action {
    Allow,
    Reject,
}

// Built-in default ruleset containing all standard Matrix federation endpoints.
// Override rules from external toml files take precedence over these defaults.
// Those endpoints are ALL allowed.
pub(crate) static DEFAULT_RULESET: Lazy<Vec<RegexEndpoint>> = Lazy::new(|| {
    use AuthType::*;
    use EndpointType::*;

    vec![
        // 2.1 Resolving server names
        RegexEndpoint::new_allowed(
            "well_known_server",
            "/.well-known/matrix/server",
            Some(Method::GET),
            Unauthenticated,
            WellKnown,
        )
        .expect("Invalid endpoint definition"),
        // 2.2 Server implementation
        RegexEndpoint::new_allowed(
            "federation_version",
            "/_matrix/federation/v1/version",
            Some(Method::GET),
            Unauthenticated,
            WellKnown,
        )
        .expect("Invalid endpoint definition"),
        // 2.3 Retrieving server keys
        RegexEndpoint::new_allowed(
            "key_v2_server",
            "/_matrix/key/v2/server",
            Some(Method::GET),
            Unauthenticated,
            WellKnown,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "key_v2_query_post",
            "/_matrix/key/v2/query",
            Some(Method::POST),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "key_v2_query_get",
            "/_matrix/key/v2/query/{server_name}",
            Some(Method::GET),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 4. Transactions
        RegexEndpoint::new_allowed(
            "send_transaction",
            "/_matrix/federation/v1/send/{txnId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 5.1.5 Retrieving event authorization information
        RegexEndpoint::new_allowed(
            "event_auth",
            "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 8. Backfilling and retrieving missing events
        RegexEndpoint::new_allowed(
            "backfill",
            "/_matrix/federation/v1/backfill/{roomId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "get_missing_events",
            "/_matrix/federation/v1/get_missing_events/{roomId}",
            Some(Method::POST),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 9. Retrieving events
        RegexEndpoint::new_allowed(
            "get_event",
            "/_matrix/federation/v1/event/{eventId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "get_state",
            "/_matrix/federation/v1/state/{roomId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "get_state_ids",
            "/_matrix/federation/v1/state_ids/{roomId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "timestamp_to_event",
            "/_matrix/federation/v1/timestamp_to_event/{roomId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 10. Joining rooms
        RegexEndpoint::new_allowed(
            "make_join",
            "/_matrix/federation/v1/make_join/{roomId}/{userId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "send_join_v1",
            "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "send_join_v2",
            "/_matrix/federation/v2/send_join/{roomId}/{eventId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 11. Knocking
        RegexEndpoint::new_allowed(
            "make_knock",
            "/_matrix/federation/v1/make_knock/{roomId}/{userId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "send_knock",
            "/_matrix/federation/v1/send_knock/{roomId}/{eventId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 12. Inviting
        RegexEndpoint::new_allowed(
            "invite_v1",
            "/_matrix/federation/v1/invite/{roomId}/{eventId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "invite_v2",
            "/_matrix/federation/v2/invite/{roomId}/{eventId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 13. Leaving rooms
        RegexEndpoint::new_allowed(
            "make_leave",
            "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "send_leave_v1",
            "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "send_leave_v2",
            "/_matrix/federation/v2/send_leave/{roomId}/{eventId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 14. Third-party invites
        RegexEndpoint::new_allowed(
            "3pid_onbind",
            "/_matrix/federation/v1/3pid/onbind",
            Some(Method::PUT),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "exchange_third_party_invite",
            "/_matrix/federation/v1/exchange_third_party_invite/{roomId}",
            Some(Method::PUT),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 15. Public room directory
        RegexEndpoint::new_allowed(
            "public_rooms_get",
            "/_matrix/federation/v1/publicRooms",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "public_rooms_post",
            "/_matrix/federation/v1/publicRooms",
            Some(Method::POST),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 16. Spaces
        RegexEndpoint::new_allowed(
            "spaces_hierarchy",
            "/_matrix/federation/v1/hierarchy/{roomId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 20. Querying for information
        RegexEndpoint::new_allowed(
            "query_directory",
            "/_matrix/federation/v1/query/directory",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "query_profile",
            "/_matrix/federation/v1/query/profile",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "query_generic",
            "/_matrix/federation/v1/query/{queryType}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 21. OpenID
        RegexEndpoint::new_allowed(
            "openid_userinfo",
            "/_matrix/federation/v1/openid/userinfo",
            Some(Method::GET),
            Unauthenticated,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 22. Device management
        RegexEndpoint::new_allowed(
            "user_devices",
            "/_matrix/federation/v1/user/devices/{userId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 23. End-to-end encryption
        RegexEndpoint::new_allowed(
            "user_keys_claim",
            "/_matrix/federation/v1/user/keys/claim",
            Some(Method::POST),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "user_keys_query",
            "/_matrix/federation/v1/user/keys/query",
            Some(Method::POST),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 25. Content repository
        RegexEndpoint::new_allowed(
            "media_download",
            "/_matrix/federation/v1/media/download/{mediaId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        RegexEndpoint::new_allowed(
            "media_thumbnail",
            "/_matrix/federation/v1/media/thumbnail/{mediaId}",
            Some(Method::GET),
            CheckSignature,
            Federation,
        )
        .expect("Invalid endpoint definition"),
        // 25bis. Legacy content repository (any method)
        RegexEndpoint::new_allowed(
            "legacy_media",
            "/_matrix/media/{path}",
            None,
            Unauthenticated,
            LegacyMedia,
        )
        .expect("Invalid endpoint definition"),
        // Needed for legacy content repository discovery
        RegexEndpoint::new_allowed(
            "well_known_client",
            "/.well-known/matrix/client",
            Some(Method::GET),
            Unauthenticated,
            WellKnown,
        )
        .expect("Invalid endpoint definition"),
    ]
});
