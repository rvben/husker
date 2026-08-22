use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::{CoreError, EgressRuleRequest};

const MAX_REQUESTED_EGRESS_RULES: usize = 32;
const MAX_RESOLVED_EGRESS_RULES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ResolvedEgressRule {
    pub destination: Ipv4Addr,
    pub protocol: String,
    pub port: u16,
}

pub(crate) async fn resolve_egress_rules(
    requested: &[EgressRuleRequest],
) -> Result<Vec<ResolvedEgressRule>, CoreError> {
    if requested.len() > MAX_REQUESTED_EGRESS_RULES {
        return Err(CoreError::InvalidArgument(format!(
            "egress accepts at most {MAX_REQUESTED_EGRESS_RULES} destination rules"
        )));
    }

    let mut resolved = BTreeSet::new();
    for (index, rule) in requested.iter().enumerate() {
        let path = format!("egress[{index}]");
        let host = validate_host(&rule.host)
            .map_err(|message| CoreError::InvalidArgument(format!("{path}.host {message}")))?;
        if rule.port == 0 {
            return Err(CoreError::InvalidArgument(format!(
                "{path}.port must be between 1 and 65535"
            )));
        }
        let protocol = rule.protocol.to_ascii_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            return Err(CoreError::InvalidArgument(format!(
                "{path}.protocol must be tcp or udp"
            )));
        }

        let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ip) => vec![ip],
                IpAddr::V6(_) => {
                    return Err(CoreError::InvalidArgument(format!(
                        "{path}.host must resolve to IPv4; IPv6 egress is not supported"
                    )));
                }
            }
        } else {
            let lookup = tokio::net::lookup_host((host.as_str(), rule.port))
                .await
                .map_err(|error| {
                    CoreError::InvalidArgument(format!(
                        "{path}.host could not be resolved: {error}"
                    ))
                })?;
            lookup
                .filter_map(|address| match address.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        if addresses.is_empty() {
            return Err(CoreError::InvalidArgument(format!(
                "{path}.host resolved to no IPv4 addresses"
            )));
        }
        for destination in addresses {
            if destination.is_unspecified()
                || destination.is_multicast()
                || destination == Ipv4Addr::BROADCAST
            {
                return Err(CoreError::InvalidArgument(format!(
                    "{path}.host resolved to non-unicast address {destination}"
                )));
            }
            resolved.insert(ResolvedEgressRule {
                destination,
                protocol: protocol.clone(),
                port: rule.port,
            });
            if resolved.len() > MAX_RESOLVED_EGRESS_RULES {
                return Err(CoreError::InvalidArgument(format!(
                    "egress resolves to more than {MAX_RESOLVED_EGRESS_RULES} concrete destinations"
                )));
            }
        }
    }
    Ok(resolved.into_iter().collect())
}

fn validate_host(value: &str) -> Result<String, &'static str> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() {
        return Err("is required");
    }
    if value.len() > 253 {
        return Err("must be at most 253 bytes");
    }
    if value.contains("://") || value.contains('/') || value.contains('*') {
        return Err("must be a hostname or IP address without a scheme, path, or wildcard");
    }
    if value.chars().any(|character| {
        character.is_control() || character.is_whitespace() || !character.is_ascii()
    }) {
        return Err("must contain only printable ASCII hostname characters");
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(value.to_string());
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err("is not a valid DNS hostname");
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_and_deduplicates_literal_destinations() {
        let resolved = resolve_egress_rules(&[
            EgressRuleRequest {
                host: "203.0.113.8".into(),
                port: 443,
                protocol: "tcp".into(),
            },
            EgressRuleRequest {
                host: "203.0.113.8".into(),
                port: 443,
                protocol: "TCP".into(),
            },
        ])
        .await
        .unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].destination,
            "203.0.113.8".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(resolved[0].protocol, "tcp");
    }

    #[tokio::test]
    async fn rejects_urls_wildcards_and_unsupported_protocols() {
        for host in ["https://example.com", "*.example.com", "example.com/path"] {
            let error = resolve_egress_rules(&[EgressRuleRequest {
                host: host.into(),
                port: 443,
                protocol: "tcp".into(),
            }])
            .await
            .unwrap_err();
            assert!(error.to_string().contains("hostname or IP address"));
        }
        let error = resolve_egress_rules(&[EgressRuleRequest {
            host: "203.0.113.8".into(),
            port: 53,
            protocol: "sctp".into(),
        }])
        .await
        .unwrap_err();
        assert!(error.to_string().contains("must be tcp or udp"));
    }

    #[tokio::test]
    async fn rejects_non_unicast_and_zero_port() {
        for host in ["0.0.0.0", "224.0.0.1", "255.255.255.255"] {
            let error = resolve_egress_rules(&[EgressRuleRequest {
                host: host.into(),
                port: 443,
                protocol: "tcp".into(),
            }])
            .await
            .unwrap_err();
            assert!(error.to_string().contains("non-unicast"));
        }
        let error = resolve_egress_rules(&[EgressRuleRequest {
            host: "203.0.113.8".into(),
            port: 0,
            protocol: "tcp".into(),
        }])
        .await
        .unwrap_err();
        assert!(error.to_string().contains("between 1 and 65535"));
    }
}
