use std::{collections::BTreeMap, net::SocketAddr};

use crate::{
    http_gateway::{
        util::create_status_response, GatewayDirection, GatewayHandler, RequestOrResponse,
    },
    matrix::{
        spec::{Action, AuthType, WHITELISTED_ENDPOINTS},
        util::{create_matrix_response, NameResolver},
        xmatrix::verify_signature,
    },
    util::{get_matching_endpoint, to_bytes, RegexEndpoint, RequestContext},
};
use http::{Request, StatusCode};
use log::Level;
use reqwest::Body;
use ruma::{api::federation::authentication::XMatrix, serde::Base64};

#[derive(Clone)]
pub struct InboundHandler {
    name_resolver: NameResolver,
    public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
    /// Per-server-name ruleset. Requests from servers without a configured ruleset are rejected.
    server_rulesets: BTreeMap<String, Vec<RegexEndpoint>>,
}

impl GatewayHandler for InboundHandler {
    async fn handle_request(
        &mut self,
        req: Request<Body>,
        direction: GatewayDirection,
        client_addr: SocketAddr,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();

        let mut ctx = RequestContext::new(parts, direction, client_addr, &mut self.name_resolver);

        // Check whitelisted endpoints first before any other validation
        if let Some(endpoint) = get_matching_endpoint(&ctx.parts, &WHITELISTED_ENDPOINTS) {
            if endpoint.rule.inbound_action == Action::Allow {
                ctx.log(Level::Info, "forward, whitelisted endpoint");
                return Request::from_parts(ctx.parts, body).into();
            }
        }

        // If rdns failed (returns IP address), try to extract origin from X-Matrix header
        if ctx.origin_server_name.parse::<std::net::IpAddr>().is_ok() {
            if let Some(auth_header) = ctx.parts.headers.get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Ok(x_matrix) = XMatrix::parse(auth_str) {
                        ctx.origin_server_name = x_matrix.origin.to_string();
                    }
                }
            }
        }

        // Use the origin server name (from rdns or Host header) to pick the ruleset.
        // Note: For authenticated endpoints, the X-Matrix origin will be validated in check_signature.
        let Some(server_rules) = self
            .server_rulesets
            .get(&ctx.origin_server_name)
            .map(Vec::as_slice)
        else {
            ctx.log(Level::Warn, "403 - forbidden, server not on allow list");
            return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
        };

        let Some(endpoint) = get_matching_endpoint(&ctx.parts, server_rules) else {
            ctx.log(Level::Warn, "404 - not found, unknown endpoint");
            return create_status_response(StatusCode::NOT_FOUND).into();
        };

        // Verifying the auth type, and if a specific endpoint is authorized or not.
        match endpoint.rule.auth_type {
            AuthType::Unauthenticated => {
                if endpoint.rule.inbound_action == Action::Reject {
                    ctx.log(Level::Warn, "403 - forbidden, endpoint rejected by ruleset");
                    return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
                }
                ctx.log(Level::Info, "forward, unauthenticated endpoint");
                Request::from_parts(ctx.parts, body).into()
            }
            AuthType::CheckSignature => {
                self.check_signature(ctx, body, endpoint.rule.inbound_action)
                    .await
            }
        }
    }
}

impl InboundHandler {
    pub fn new(
        name_resolver: NameResolver,
        public_key_map: BTreeMap<String, BTreeMap<String, Base64>>,
        server_rulesets: BTreeMap<String, Vec<RegexEndpoint>>,
    ) -> Self {
        Self {
            name_resolver,
            public_key_map,
            server_rulesets,
        }
    }

    async fn check_signature(
        &self,
        mut ctx: RequestContext,
        body: Body,
        inbound_action: Action,
    ) -> RequestOrResponse {
        let Some(auth_header) = ctx.parts.headers.get("Authorization") else {
            ctx.log(Level::Warn, "401 - unauthorized, no authorization header");
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        };

        let Ok(x_matrix) = XMatrix::parse(auth_header.to_str().unwrap_or_default()) else {
            ctx.log(
                Level::Warn,
                "401 - unauthorized, invalid X-Matrix auth header",
            );
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        };

        // let's override the origin with the server name from the X-Matrix header
        ctx.origin_server_name = x_matrix.origin.clone().to_string();

        if !self
            .public_key_map
            .contains_key(ctx.origin_server_name.as_str())
        {
            ctx.log(Level::Warn, "401 - unauthorized, unauthorized server");
            return create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into();
        }

        if inbound_action == Action::Reject {
            ctx.log(Level::Warn, "403 - forbidden, endpoint rejected by ruleset");
            return create_matrix_response(StatusCode::FORBIDDEN, "M_FORBIDDEN").into();
        }

        let Some(body) = to_bytes(body, 1024 * 1024 * 10).await else {
            ctx.log(Level::Warn, "413 - req body too large");
            return create_status_response(StatusCode::PAYLOAD_TOO_LARGE).into();
        };

        let Ok(body) = String::from_utf8(body.to_vec()) else {
            ctx.log(Level::Warn, "400 - bad request, req body not utf8");
            return create_status_response(StatusCode::BAD_REQUEST).into();
        };

        match verify_signature(&self.public_key_map, &ctx.parts, x_matrix, &body) {
            Ok(()) => {
                ctx.log(
                    Level::Info,
                    "forward, authorized server and valid signature",
                );
                Request::from_parts(ctx.parts, Body::from(body)).into()
            }
            Err(e) => {
                ctx.log(
                    Level::Warn,
                    &format!("401 - unauthorized, authorized server but wrong signature: {e}"),
                );
                create_matrix_response(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED").into()
            }
        }
    }
}
