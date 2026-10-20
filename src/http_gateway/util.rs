use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use http::{
    HeaderMap, HeaderValue, StatusCode,
    header::{CONNECTION, HOST, HeaderName, TE, TRAILER, TRANSFER_ENCODING, UPGRADE},
    request::Parts,
    uri::Authority,
};
use ipnet::IpNet;

use crate::http_gateway::GatewayDirection;

const FORWARDED: HeaderName = HeaderName::from_static("forwarded");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const PROXY_AUTHORIZATION: HeaderName = HeaderName::from_static("proxy-authorization");
const PROXY_AUTHENTICATE: HeaderName = HeaderName::from_static("proxy-authenticate");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");

#[derive(Clone, Debug)]
pub(crate) struct InboundRequestMetadata {
    pub(crate) destination_host: String,
    pub(crate) origin_ip: IpAddr,
}

pub(crate) async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

pub(crate) fn create_response<B: From<String>>(
    status: StatusCode,
    body_and_content_type: Option<(B, &str)>,
) -> Result<http::Response<B>, http::Error> {
    let builder = http::Response::builder().status(status);
    if let Some((body, content_type)) = body_and_content_type {
        return builder.header("Content-Type", content_type).body(body);
    }
    builder.body(B::from("".to_string()))
}

pub(crate) fn create_status_response<B: From<String>>(status: StatusCode) -> http::Response<B> {
    #[allow(clippy::unwrap_used, reason = "no untrusted input")]
    create_response(status, None).unwrap()
}

/// Capture forwarding metadata once, at the inbound network boundary. Forwarding headers are
/// honored only when the immediate peer belongs to an explicitly configured trusted network.
pub(crate) fn capture_inbound_request_metadata(
    parts: &Parts,
    client_addr: &SocketAddr,
    trusted_proxies: &[IpNet],
) -> InboundRequestMetadata {
    let peer_ip = client_addr.ip();
    let peer_is_trusted = is_trusted(peer_ip, trusted_proxies);

    let direct_host = request_host(parts).unwrap_or_default();
    let destination_host = if peer_is_trusted {
        forwarded_host(&parts.headers).unwrap_or(direct_host)
    } else {
        direct_host
    };

    let origin_ip = if peer_is_trusted {
        forwarded_for_chain(&parts.headers)
            .and_then(|chain| first_untrusted_from_right(&chain, trusted_proxies))
            .unwrap_or(peer_ip)
    } else {
        peer_ip
    };

    InboundRequestMetadata {
        destination_host,
        origin_ip,
    }
}

pub(crate) fn extract_destination_host(parts: &Parts, direction: &GatewayDirection) -> String {
    if direction == &GatewayDirection::Inbound
        && let Some(metadata) = parts.extensions.get::<InboundRequestMetadata>()
    {
        return metadata.destination_host.clone();
    }

    match direction {
        GatewayDirection::Inbound => request_host(parts).unwrap_or_default(),
        GatewayDirection::Outbound => parts
            .uri
            .authority()
            .and_then(|authority| normalize_authority(authority.as_str()))
            .or_else(|| request_host(parts))
            .unwrap_or_default(),
    }
}

pub(crate) fn extract_origin_ip(
    parts: &Parts,
    direction: &GatewayDirection,
    client_addr: &SocketAddr,
) -> IpAddr {
    if direction == &GatewayDirection::Inbound
        && let Some(metadata) = parts.extensions.get::<InboundRequestMetadata>()
    {
        return metadata.origin_ip;
    }
    client_addr.ip()
}

/// Remove hop-by-hop and client-supplied forwarding headers, then add the canonical values that
/// the internal homeserver is allowed to trust.
pub(crate) fn sanitize_inbound_request_headers(
    headers: &mut HeaderMap,
    destination_host: &str,
    origin_ip: IpAddr,
) {
    remove_hop_by_hop_headers(headers);
    remove_forwarding_headers(headers);
    headers.remove(HOST);

    if let Ok(host) = HeaderValue::from_str(destination_host) {
        headers.insert(HOST, host.clone());
        headers.insert(X_FORWARDED_HOST, host);
    }
    if let Ok(origin) = HeaderValue::from_str(&origin_ip.to_string()) {
        headers.insert(X_FORWARDED_FOR, origin);
    }
}

/// Sanitize a forward-proxy request before it leaves the gateway. In particular, proxy
/// credentials and internal forwarding metadata must never reach the origin server.
pub(crate) fn sanitize_outbound_request_headers(
    headers: &mut HeaderMap,
    destination_authority: Option<&Authority>,
) {
    remove_hop_by_hop_headers(headers);
    remove_forwarding_headers(headers);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove(HOST);

    if let Some(authority) = destination_authority
        && let Ok(host) = HeaderValue::from_str(authority.as_str())
    {
        headers.insert(HOST, host);
    }
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_str(name.trim()).ok())
        .collect::<Vec<_>>();

    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        KEEP_ALIVE,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        PROXY_CONNECTION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn remove_forwarding_headers(headers: &mut HeaderMap) {
    headers.remove(FORWARDED);
    headers.remove(X_FORWARDED_FOR);
    headers.remove(X_FORWARDED_HOST);
}

fn request_host(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_authority)
        .or_else(|| {
            parts
                .uri
                .authority()
                .and_then(|authority| normalize_authority(authority.as_str()))
        })
}

fn forwarded_host(headers: &HeaderMap) -> Option<String> {
    let from_x_forwarded_host = headers
        .get_all(&X_FORWARDED_HOST)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .rfind(|value| !value.is_empty())
        .and_then(normalize_authority);

    from_x_forwarded_host.or_else(|| {
        forwarded_parameters(headers, "host")
            .last()
            .and_then(|value| normalize_authority(value))
    })
}

fn normalize_authority(value: &str) -> Option<String> {
    let authority = Authority::from_str(value.trim()).ok()?;
    Some(remove_default_http_https_port(authority.as_str()).to_ascii_lowercase())
}

fn forwarded_for_chain(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    let x_forwarded_values = headers
        .get_all(&X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    if !x_forwarded_values.is_empty() {
        return x_forwarded_values
            .into_iter()
            .map(parse_forwarded_ip)
            .collect();
    }

    let forwarded_values = forwarded_parameters(headers, "for");
    if forwarded_values.is_empty() {
        None
    } else {
        forwarded_values
            .into_iter()
            .map(parse_forwarded_ip)
            .collect()
    }
}

fn forwarded_parameters<'a>(headers: &'a HeaderMap, requested: &str) -> Vec<&'a str> {
    let mut values = Vec::new();
    for header in headers.get_all(&FORWARDED) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for element in split_quoted(header, ',') {
            for parameter in split_quoted(element, ';') {
                let Some((name, value)) = parameter.split_once('=') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case(requested) {
                    values.push(trim_optional_quotes(value.trim()));
                }
            }
        }
    }
    values
}

fn split_quoted(value: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quoted {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == delimiter && !quoted {
            parts.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    parts.push(&value[start..]);
    parts
}

fn trim_optional_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = trim_optional_quotes(value.trim());
    if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }
    if let Some(bracketed) = value.strip_prefix('[') {
        let end = bracketed.find(']')?;
        return bracketed[..end].parse().ok();
    }
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
}

fn first_untrusted_from_right(chain: &[IpAddr], trusted_proxies: &[IpNet]) -> Option<IpAddr> {
    chain
        .iter()
        .rev()
        .copied()
        .find(|address| !is_trusted(*address, trusted_proxies))
        .or_else(|| chain.first().copied())
}

fn is_trusted(address: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies
        .iter()
        .any(|network| network.contains(&address))
}

pub(crate) fn remove_default_http_https_port(host: &str) -> &str {
    if host.ends_with(":443") {
        host.split_at(host.len() - 4).0
    } else if host.ends_with(":80") {
        host.split_at(host.len() - 3).0
    } else {
        host
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn parts(headers: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder()
            .uri("/test")
            .header(HOST, "direct.example");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(())
            .expect("test request should be valid")
            .into_parts()
            .0
    }

    #[test]
    fn untrusted_peer_cannot_supply_forwarding_metadata() {
        let parts = parts(&[
            ("x-forwarded-host", "spoofed.example"),
            ("x-forwarded-for", "203.0.113.8"),
        ]);
        let peer: SocketAddr = "192.0.2.10:1234".parse().expect("valid peer address");

        let metadata = capture_inbound_request_metadata(&parts, &peer, &[]);
        assert_eq!(metadata.destination_host, "direct.example");
        assert_eq!(metadata.origin_ip, peer.ip());
    }

    #[test]
    fn trusted_proxy_parses_multi_hop_x_forwarded_for() {
        let parts = parts(&[("x-forwarded-for", "198.51.100.7, 10.1.2.3, 10.2.3.4")]);
        let peer: SocketAddr = "10.3.4.5:1234".parse().expect("valid peer address");
        let trusted = ["10.0.0.0/8".parse().expect("valid network")];

        let metadata = capture_inbound_request_metadata(&parts, &peer, &trusted);
        assert_eq!(
            metadata.origin_ip,
            "198.51.100.7".parse::<IpAddr>().expect("valid address")
        );
    }

    #[test]
    fn trusted_proxy_parses_standard_forwarded_header() {
        let parts = parts(&[(
            "forwarded",
            "for=192.0.2.60;proto=https;host=matrix.example, for=10.0.0.2",
        )]);
        let peer: SocketAddr = "10.0.0.3:1234".parse().expect("valid peer address");
        let trusted = ["10.0.0.0/8".parse().expect("valid network")];

        let metadata = capture_inbound_request_metadata(&parts, &peer, &trusted);
        assert_eq!(metadata.destination_host, "matrix.example");
        assert_eq!(
            metadata.origin_ip,
            "192.0.2.60".parse::<IpAddr>().expect("valid address")
        );
    }

    #[test]
    fn sanitization_removes_hop_headers_and_proxy_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("x-remove, keep-alive"));
        headers.insert(
            HeaderName::from_static("x-remove"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic secret"),
        );
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("203.0.113.9"));

        let authority: Authority = "origin.example:8448"
            .parse()
            .expect("valid destination authority");
        sanitize_outbound_request_headers(&mut headers, Some(&authority));

        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("x-remove"));
        assert!(!headers.contains_key(PROXY_AUTHORIZATION));
        assert!(!headers.contains_key(X_FORWARDED_FOR));
        assert_eq!(
            headers.get(HOST),
            Some(&HeaderValue::from_static("origin.example:8448"))
        );
    }
}
