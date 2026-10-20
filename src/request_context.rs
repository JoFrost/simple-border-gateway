use std::net::SocketAddr;

use http::request::Parts;
use log::{Level, log};
use ruma::api::federation::authentication::XMatrix;

use crate::{
    http_gateway::{
        GatewayDirection,
        util::{extract_destination_host, extract_origin_ip},
    },
    matrix::util::NameResolver,
};

pub(crate) struct RequestContext {
    pub(crate) parts: Parts,
    pub(crate) xmatrix: Option<XMatrix>,
    pub(crate) origin_server_name: String,
    pub(crate) destination_server_name: String,
    pub(crate) destination_host: String,
    log_prefix: String,
}

impl RequestContext {
    pub(crate) async fn new(
        parts: Parts,
        direction: GatewayDirection,
        client_addr: SocketAddr,
        name_resolver: &NameResolver,
    ) -> Self {
        let xmatrix = parts
            .headers
            .get("Authorization")
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_str| XMatrix::parse(auth_str).ok());

        let origin_server_name = if let Some(xmatrix) = &xmatrix {
            xmatrix.origin.to_string()
        } else {
            let origin_ip = extract_origin_ip(&parts, &direction, &client_addr);
            name_resolver.ip_to_server_name(&origin_ip).await
        };

        let destination_host = extract_destination_host(&parts, &direction);
        Self {
            parts,
            xmatrix,
            origin_server_name,
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
