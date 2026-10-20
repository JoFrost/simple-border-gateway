use crate::cli::Cli;
use crate::config::BorderGatewayConfig;
use crate::crypto::crypto_provider;
use crate::endpoint::{
    CompiledRuleset, EndpointCompileError, build_endpoint_router_from_endpoint_configs,
    compile_override_rules,
};
use crate::http_client::{HttpClientError, PemError, create_http_client, read_pem};
use crate::http_gateway::inbound::InboundGatewayBuilder;
use crate::http_gateway::outbound::{OutboundGatewayBuilder, OutboundGatewayCreateError};
use crate::inbound::InboundHandler;
use crate::matrix::util::NameResolver;
use crate::outbound::OutboundHandler;
use ipnet::IpNet;
use log::{debug, error, info};
use snafu::{Report, Snafu};
use tokio::task::JoinHandle;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{AddrParseError, IpAddr};
use std::process::exit;

use ruma::{serde::Base64, signatures::PublicKeyMap};

#[derive(Debug, Snafu)]
pub enum PrepareServiceError {
    #[snafu(display("Duplicate homeserver server_name '{server_name}'"))]
    DuplicateServerName { server_name: String },
    #[snafu(display("Duplicate homeserver federation_domain '{domain}'"))]
    DuplicateFederationDomain { domain: String },
    #[snafu(display("Duplicate homeserver client_domain '{domain}'"))]
    DuplicateClientDomain { domain: String },
    #[snafu(display(
        "Domain '{domain}' is assigned to both homeserver '{existing_server}' and '{new_server}'"
    ))]
    DuplicateRoutingDomain {
        domain: String,
        existing_server: String,
        new_server: String,
    },
    #[snafu(display("Inbound target host '{host}' is declared more than once"))]
    DuplicateTargetHost { host: String },
    #[snafu(display("Ruleset name cannot be empty"))]
    EmptyRulesetName,
    #[snafu(display("Ruleset '{name}' is defined more than once"))]
    DuplicateRuleset { name: String },
    #[snafu(display("Failed to compile ruleset '{ruleset}'"))]
    CompileRuleset {
        ruleset: String,
        source: EndpointCompileError,
    },
    #[snafu(display("Homeserver '{server_name}' references unknown ruleset '{ruleset}'"))]
    UnknownRuleset {
        server_name: String,
        ruleset: String,
    },
    #[snafu(display(
        "Failed to parse verify key '{key_id}' for homeserver '{server_name}': {details}"
    ))]
    InvalidVerifyKey {
        server_name: String,
        key_id: String,
        details: String,
    },
    #[snafu(display("Invalid trusted proxy address or network '{value}'"))]
    InvalidTrustedProxy { value: String },
    #[snafu(display("Failed to create inbound HTTP client"))]
    InboundHttpClient { source: HttpClientError },
    #[snafu(display("Failed to parse inbound listen address '{address}'"))]
    InboundListenAddress {
        address: String,
        source: AddrParseError,
    },
    #[snafu(display("Failed to create outbound HTTP client"))]
    OutboundHttpClient { source: HttpClientError },
    #[snafu(display("Failed to compile non-Matrix outbound endpoints"))]
    OutboundEndpoints { source: EndpointCompileError },
    #[snafu(display("Failed to read outbound CA private key"))]
    CaPrivateKey { source: PemError },
    #[snafu(display("Failed to read outbound CA certificate"))]
    CaCertificate { source: PemError },
    #[snafu(display("Failed to parse outbound listen address '{address}'"))]
    OutboundListenAddress {
        address: String,
        source: AddrParseError,
    },
    #[snafu(display("Failed to create outbound gateway"))]
    OutboundGateway { source: OutboundGatewayCreateError },
}

/// A service whose configuration has been fully validated and compiled, ready to be spawned.
///
/// All fallible configuration work (regex compilation, address parsing, certificate
/// loading, ...) happens while building these, which lets a config reload reject a bad
/// configuration before the currently running services are stopped.
pub enum PreparedService {
    Inbound(InboundGatewayBuilder<InboundHandler>),
    Outbound(Box<OutboundGatewayBuilder<OutboundHandler>>),
}

/// Validates the configuration and builds the corresponding services without starting them.
pub fn prepare_services(
    config: BorderGatewayConfig,
    cli: &Cli,
) -> Result<Vec<PreparedService>, PrepareServiceError> {
    debug!("Configuration loaded");
    let BorderGatewayConfig {
        internal_homeservers,
        external_homeservers,
        inbound_proxy,
        outbound_proxy,
        rulesets,
    } = config;

    let mut domain_server_name_map = BTreeMap::new();
    let mut target_base_urls: BTreeMap<String, String> = BTreeMap::new();
    let mut server_names = BTreeSet::new();
    let mut federation_domains = BTreeSet::new();
    let mut client_domains = BTreeSet::new();

    for hs in internal_homeservers {
        debug!(
            "Internal homeserver {} with federation domain {} and target base url {}",
            hs.server_name, hs.federation_domain, hs.target_base_url
        );
        ensure_unique_server_name(&mut server_names, &hs.server_name)?;
        ensure_unique_federation_domain(&mut federation_domains, &hs.federation_domain)?;
        insert_routing_domain(
            &mut domain_server_name_map,
            &hs.federation_domain,
            &hs.server_name,
        )?;
        insert_target(
            &mut target_base_urls,
            &hs.federation_domain,
            &hs.target_base_url,
        )?;
        if hs.server_name != hs.federation_domain {
            insert_target(&mut target_base_urls, &hs.server_name, &hs.target_base_url)?;
        }
    }

    let mut named_rulesets: BTreeMap<String, CompiledRuleset> = BTreeMap::new();
    for ruleset in &rulesets {
        if ruleset.name.is_empty() {
            return Err(PrepareServiceError::EmptyRulesetName);
        }
        if named_rulesets.contains_key(&ruleset.name) {
            return Err(PrepareServiceError::DuplicateRuleset {
                name: ruleset.name.clone(),
            });
        }
        let additional_endpoints = build_endpoint_router_from_endpoint_configs(
            &ruleset.additional_endpoints,
        )
        .map_err(|source| PrepareServiceError::CompileRuleset {
            ruleset: ruleset.name.clone(),
            source,
        })?;
        let action_overrides =
            compile_override_rules(&ruleset.override_rules, &ruleset.additional_endpoints)
                .map_err(|source| PrepareServiceError::CompileRuleset {
                    ruleset: ruleset.name.clone(),
                    source,
                })?;
        named_rulesets.insert(
            ruleset.name.clone(),
            CompiledRuleset {
                additional_endpoints,
                action_overrides,
            },
        );
    }

    let mut allowed_federation_domains: BTreeMap<String, String> = BTreeMap::new();
    let mut allowed_client_domains: BTreeMap<String, String> = BTreeMap::new();
    let mut public_key_map: PublicKeyMap = BTreeMap::new();
    let mut server_rulesets: BTreeMap<String, CompiledRuleset> = BTreeMap::new();

    for hs in external_homeservers {
        debug!(
            "External homeserver {} with federation domain {} and client domain {}",
            hs.server_name, hs.federation_domain, hs.client_domain
        );
        ensure_unique_server_name(&mut server_names, &hs.server_name)?;
        ensure_unique_federation_domain(&mut federation_domains, &hs.federation_domain)?;
        if !client_domains.insert(hs.client_domain.clone()) {
            return Err(PrepareServiceError::DuplicateClientDomain {
                domain: hs.client_domain,
            });
        }

        insert_routing_domain(
            &mut domain_server_name_map,
            &hs.federation_domain,
            &hs.server_name,
        )?;
        if hs.client_domain != hs.federation_domain {
            insert_routing_domain(
                &mut domain_server_name_map,
                &hs.client_domain,
                &hs.server_name,
            )?;
        }
        allowed_federation_domains.insert(hs.federation_domain.clone(), hs.server_name.clone());
        allowed_client_domains.insert(hs.client_domain.clone(), hs.server_name.clone());

        let mut verify_keys: BTreeMap<String, Base64> = BTreeMap::new();
        for (k, v) in hs.verify_keys {
            let value =
                Base64::parse(v).map_err(|source| PrepareServiceError::InvalidVerifyKey {
                    server_name: hs.server_name.clone(),
                    key_id: k.clone(),
                    details: source.to_string(),
                })?;
            verify_keys.insert(k, value);
        }

        let compiled_ruleset = match &hs.ruleset {
            Some(name) => match named_rulesets.get(name) {
                Some(e) => {
                    info!(
                        "Using override ruleset '{}' for homeserver '{}'",
                        name, hs.server_name
                    );
                    e.clone()
                }
                None => {
                    return Err(PrepareServiceError::UnknownRuleset {
                        server_name: hs.server_name,
                        ruleset: name.clone(),
                    });
                }
            },
            None => {
                info!("Using default ruleset for homeserver '{}'", hs.server_name);
                CompiledRuleset::default()
            }
        };
        server_rulesets.insert(hs.server_name.clone(), compiled_ruleset);

        public_key_map.insert(hs.server_name, verify_keys);
    }

    let mut services = vec![];
    let name_resolver = NameResolver::new(domain_server_name_map);

    if let Some(inbound_config) = inbound_proxy {
        if cli.outbound_only {
            info!(
                "Inbound proxy is configured but --outbound-only is set, inbound proxy will not be started"
            );
        } else {
            let trusted_proxies = inbound_config
                .trusted_proxies
                .iter()
                .map(|value| parse_trusted_proxy(value))
                .collect::<Result<Vec<_>, _>>()?;
            let http_client = create_http_client(inbound_config.additional_root_certs, None)
                .map_err(|source| PrepareServiceError::InboundHttpClient { source })?;
            let handler = InboundHandler::new(
                name_resolver.clone(),
                public_key_map,
                server_rulesets.clone(),
                cli.reject_all_by_default,
            );

            let listen_address = inbound_config.listen_address.parse().map_err(|source| {
                PrepareServiceError::InboundListenAddress {
                    address: inbound_config.listen_address,
                    source,
                }
            })?;

            services.push(PreparedService::Inbound(
                InboundGatewayBuilder::new(listen_address, target_base_urls, handler)
                    .with_http_client(http_client)
                    .with_trusted_proxies(trusted_proxies),
            ));
            info!("Inbound proxy initialized");
        }
    }

    if let Some(outbound_config) = outbound_proxy {
        if cli.inbound_only {
            info!(
                "Outbound proxy is configured but --inbound-only is set, outbound proxy will not be started"
            );
        } else {
            let http_client = create_http_client(
                outbound_config.additional_root_certs,
                outbound_config.upstream_proxy,
            )
            .map_err(|source| PrepareServiceError::OutboundHttpClient { source })?;
            let handler = OutboundHandler::new(
                name_resolver,
                allowed_federation_domains,
                allowed_client_domains,
                outbound_config.hazmat_non_matrix_endpoints,
                server_rulesets,
                cli.reject_all_by_default,
            )
            .map_err(|source| PrepareServiceError::OutboundEndpoints { source })?;

            let ca_private_key = read_pem(outbound_config.ca_priv_key.as_str())
                .map_err(|source| PrepareServiceError::CaPrivateKey { source })?;
            let ca_cert = read_pem(&outbound_config.ca_cert)
                .map_err(|source| PrepareServiceError::CaCertificate { source })?;

            let listen_address = outbound_config.listen_address.parse().map_err(|source| {
                PrepareServiceError::OutboundListenAddress {
                    address: outbound_config.listen_address,
                    source,
                }
            })?;

            let builder = OutboundGatewayBuilder::new(
                listen_address,
                ca_private_key,
                ca_cert,
                crypto_provider::default_provider(),
                handler,
            )
            .map_err(|source| PrepareServiceError::OutboundGateway { source })?
            .with_http_client(http_client);
            services.push(PreparedService::Outbound(Box::new(builder)));
            info!("Outbound proxy initialized");
        }
    }
    Ok(services)
}

fn ensure_unique_server_name(
    server_names: &mut BTreeSet<String>,
    server_name: &str,
) -> Result<(), PrepareServiceError> {
    if !server_names.insert(server_name.to_string()) {
        return Err(PrepareServiceError::DuplicateServerName {
            server_name: server_name.to_string(),
        });
    }
    Ok(())
}

fn ensure_unique_federation_domain(
    federation_domains: &mut BTreeSet<String>,
    domain: &str,
) -> Result<(), PrepareServiceError> {
    if !federation_domains.insert(domain.to_string()) {
        return Err(PrepareServiceError::DuplicateFederationDomain {
            domain: domain.to_string(),
        });
    }
    Ok(())
}

fn insert_routing_domain(
    domains: &mut BTreeMap<String, String>,
    domain: &str,
    server_name: &str,
) -> Result<(), PrepareServiceError> {
    if let Some(existing_server) = domains.get(domain) {
        return Err(PrepareServiceError::DuplicateRoutingDomain {
            domain: domain.to_string(),
            existing_server: existing_server.clone(),
            new_server: server_name.to_string(),
        });
    }
    domains.insert(domain.to_string(), server_name.to_string());
    Ok(())
}

fn insert_target(
    targets: &mut BTreeMap<String, String>,
    host: &str,
    target: &str,
) -> Result<(), PrepareServiceError> {
    if targets
        .insert(host.to_string(), target.to_string())
        .is_some()
    {
        return Err(PrepareServiceError::DuplicateTargetHost {
            host: host.to_string(),
        });
    }
    Ok(())
}

fn parse_trusted_proxy(value: &str) -> Result<IpNet, PrepareServiceError> {
    value
        .parse::<IpNet>()
        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| PrepareServiceError::InvalidTrustedProxy {
            value: value.to_string(),
        })
}

/// Spawns the given prepared services, returning their task handles.
pub fn spawn_services(services: Vec<PreparedService>) -> Vec<JoinHandle<()>> {
    services
        .into_iter()
        .map(|service| match service {
            PreparedService::Inbound(builder) => tokio::spawn(async move {
                if let Err(err) = builder.build_and_run().await {
                    error!("Failed to create inbound proxy");
                    error!("{}", Report::from_error(err));
                    exit(1);
                }
            }),
            PreparedService::Outbound(builder) => tokio::spawn(async move {
                if let Err(err) = builder.build_and_run().await {
                    error!("Failed to create outbound proxy");
                    error!("{}", Report::from_error(err));
                    exit(1);
                }
            }),
        })
        .collect()
}

/// Aborts the given tasks and awaits their termination.
///
/// `JoinHandle::abort` only requests cancellation; the task may still be running
/// (and holding resources such as its listening socket) when it returns. Awaiting
/// the handles guarantees the tasks have actually stopped and released their
/// resources before new services are started, avoiding `EADDRINUSE` on reload.
pub async fn stop_services(tasks: Vec<JoinHandle<()>>) {
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        // An aborted task resolves with a cancellation error, which is expected.
        let _ = task.await;
    }
}
