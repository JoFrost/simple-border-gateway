use std::{path::PathBuf, time::Duration};

use reqwest::redirect::Policy;
use snafu::Snafu;

use crate::config::UpstreamProxyConfig;

#[derive(Debug, Snafu)]
pub enum PemError {
    #[snafu(display("Failed to read PEM file {}", path.display()))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("PEM content is not valid UTF-8"))]
    InvalidUtf8 { source: std::string::FromUtf8Error },
}

#[derive(Debug, Snafu)]
pub enum HttpClientError {
    #[snafu(display("Failed to create upstream proxy configuration"))]
    InvalidProxy { source: reqwest::Error },
    #[snafu(display("Failed to read additional root certificate at index {index}"))]
    ReadRootCertificate { index: usize, source: PemError },
    #[snafu(display("Failed to parse additional root certificate at index {index}"))]
    ParseRootCertificate {
        index: usize,
        source: reqwest::Error,
    },
    #[snafu(display("Failed to build HTTP client"))]
    Build { source: reqwest::Error },
}

pub fn read_pem(path_or_content: &str) -> Result<String, PemError> {
    let bytes = if path_or_content.trim_start().starts_with("-----BEGIN ") {
        path_or_content.as_bytes().to_vec()
    } else {
        std::fs::read(path_or_content).map_err(|source| PemError::Read {
            path: PathBuf::from(path_or_content),
            source,
        })?
    };
    String::from_utf8(bytes).map_err(|source| PemError::InvalidUtf8 { source })
}

pub fn create_http_client(
    additional_root_certs: Vec<String>,
    upstream_proxy_config: Option<UpstreamProxyConfig>,
) -> Result<reqwest::Client, HttpClientError> {
    let mut builder = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30 * 60));

    if let Some(upstream_proxy_config) = upstream_proxy_config {
        let mut proxy_builder = reqwest::Proxy::all(upstream_proxy_config.url)
            .map_err(|source| HttpClientError::InvalidProxy { source })?;
        if upstream_proxy_config.username.is_some() || upstream_proxy_config.password.is_some() {
            proxy_builder = proxy_builder.basic_auth(
                upstream_proxy_config.username.as_deref().unwrap_or(""),
                upstream_proxy_config.password.as_deref().unwrap_or(""),
            );
        }
        builder = builder.proxy(proxy_builder);
    }

    let certificates = additional_root_certs
        .into_iter()
        .enumerate()
        .map(|(index, content)| {
            let pem = read_pem(&content)
                .map_err(|source| HttpClientError::ReadRootCertificate { index, source })?;
            reqwest::tls::Certificate::from_pem(pem.as_bytes())
                .map_err(|source| HttpClientError::ParseRootCertificate { index, source })
        })
        .collect::<Result<Vec<_>, _>>()?;

    builder = builder.tls_certs_merge(certificates);
    builder
        .build()
        .map_err(|source| HttpClientError::Build { source })
}
