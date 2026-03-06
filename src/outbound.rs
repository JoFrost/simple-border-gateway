use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};

use http::{Request, StatusCode};
use log::Level;
use regex::Regex;
use reqwest::Body;
use snafu::{ResultExt, Whatever};

use crate::{
    http_gateway::{
        util::create_status_response, GatewayDirection, GatewayHandler, RequestOrResponse,
    },
    matrix::{
        spec::{Action, EndpointType, WHITELISTED_ENDPOINTS},
        util::{create_matrix_response, NameResolver},
    },
    util::{get_matching_endpoint, remove_default_ports_from_uri, RegexEndpoint, RequestContext},
};

#[derive(Clone)]
pub struct OutboundHandler {
    name_resolver: NameResolver,
    allowed_server_names: HashSet<String>,
    allowed_federation_domains: HashSet<String>,
    allowed_client_domains: HashSet<String>,
    allowed_non_matrix_regexes: Vec<Regex>,
    /// Per-server-name ruleset. Requests to servers without a configured ruleset are rejected.
    server_rulesets: BTreeMap<String, Vec<RegexEndpoint>>,
}

impl GatewayHandler for OutboundHandler {
    async fn handle_request(
        &mut self,
        req: Request<Body>,
        direction: GatewayDirection,
        client_addr: SocketAddr,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();
        let ctx = RequestContext::new(parts, direction, client_addr, &mut self.name_resolver);

        // Non-matrix regexes bypass per-server ruleset routing entirely.
        let uri = remove_default_ports_from_uri(ctx.parts.uri.clone());
        for regex in &self.allowed_non_matrix_regexes {
            if regex.is_match(uri.as_str()) {
                ctx.log(Level::Info, "forward, destination uri matches regex");
                return Request::from_parts(ctx.parts, body).into();
            }
        }

        // Check if destination server is allowed
        let Some(server_rules) = self
            .server_rulesets
            .get(&ctx.destination_server_name)
            .map(Vec::as_slice)
        else {
            ctx.log(Level::Warn, "403 - forbidden, server not on allow list");
            return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
        };

        // Check whitelisted endpoints first
        if let Some(endpoint) = get_matching_endpoint(&ctx.parts, &WHITELISTED_ENDPOINTS) {
            if endpoint.rule.outbound_action == Action::Allow {
                // Still apply domain restrictions based on endpoint type
                // Federation and LegacyMedia endpoints are not whitelisted, so they should not be matched here.
                // We will check them in the server rules...
                if endpoint.rule.endpoint_type == EndpointType::WellKnown {
                    // For well-known endpoints, we want to allow requests to any server on the allow list, as well as federation domains.
                    if !self
                        .allowed_server_names
                        .contains(&ctx.destination_host.to_ascii_lowercase())
                        && !self
                            .allowed_federation_domains
                            .contains(&ctx.destination_host.to_ascii_lowercase())
                    {
                        ctx.log(Level::Warn, "403 - forbidden, unauthorized base domain");
                        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                    } else {
                        ctx.log(Level::Info, "forward, whitelisted endpoint");
                        return Request::from_parts(ctx.parts, body).into();
                    }
                }
            }
        }

        if let Some(endpoint) = get_matching_endpoint(&ctx.parts, server_rules) {
            if endpoint.rule.outbound_action == Action::Reject {
                ctx.log(Level::Warn, "403 - forbidden, endpoint rejected by ruleset");
                return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
            }

            match endpoint.rule.endpoint_type {
                EndpointType::Federation => {
                    if !self
                        .allowed_federation_domains
                        .contains(&ctx.destination_host)
                    {
                        ctx.log(
                            Level::Warn,
                            "403 - forbidden, unauthorized federation domain",
                        );
                        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                    }
                    ctx.log(Level::Info, "forward, allowed federation request");
                }
                EndpointType::LegacyMedia => {
                    if !self.allowed_client_domains.contains(&ctx.destination_host) {
                        ctx.log(Level::Warn, "403 - forbidden, unauthorized client domain");
                        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                    }
                    ctx.log(Level::Info, "forward, allowed legacy media request");
                }
                EndpointType::WellKnown => {
                    if !self.allowed_server_names.contains(&ctx.destination_host) {
                        ctx.log(Level::Warn, "403 - forbidden, unauthorized base domain");
                        return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                    }
                    ctx.log(Level::Info, "forward, allowed well known request");
                }
            }
            return Request::from_parts(ctx.parts, body).into();
        }

        ctx.log(Level::Warn, "404 - not found, unknown endpoint");
        create_status_response(StatusCode::NOT_FOUND).into()
    }
}

impl OutboundHandler {
    pub fn new(
        name_resolver: NameResolver,
        allowed_federation_domains: BTreeMap<String, String>,
        allowed_client_domains: BTreeMap<String, String>,
        allowed_non_matrix_regexes: Vec<String>,
        server_rulesets: BTreeMap<String, Vec<RegexEndpoint>>,
    ) -> Result<Self, Whatever> {
        let mut allowed_server_names =
            HashSet::from_iter(allowed_federation_domains.values().cloned());
        allowed_server_names.extend(allowed_client_domains.values().cloned());

        let allowed_non_matrix_regexes = allowed_non_matrix_regexes
            .iter()
            .map(|regex| Regex::new(regex).whatever_context("Error parsing non matrix regex"))
            .collect::<Result<Vec<Regex>, Whatever>>()?;

        Ok(Self {
            name_resolver,
            allowed_server_names,
            allowed_federation_domains: allowed_federation_domains.keys().cloned().collect(),
            allowed_client_domains: allowed_client_domains.keys().cloned().collect(),
            allowed_non_matrix_regexes,
            server_rulesets,
        })
    }
}
