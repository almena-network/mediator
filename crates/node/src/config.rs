use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};

/// Runtime configuration, read from `ALMENA_*` environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Address the HTTP server binds to (`ALMENA_HOST`, `ALMENA_PORT`).
    pub bind: SocketAddr,
    /// Log output format (`ALMENA_LOG_FORMAT`: `pretty` or `json`).
    pub log_format: LogFormat,
    /// Public origin of the node, `scheme://host[:port]` without path
    /// (`ALMENA_PUBLIC_URL`). The node's DID is the `did:web` of this origin
    /// and its DIDComm endpoint is `<origin>/didcomm`.
    pub public_url: String,
    /// JSON file holding the node's private keys (`ALMENA_KEYS_PATH`);
    /// created with fresh keys on first start.
    pub keys_path: PathBuf,
    /// Redis connection URL (`ALMENA_REDIS_URL`). `memory://` keeps
    /// everything in the process instead: development only.
    pub redis_url: String,
    /// Largest DIDComm envelope accepted, in bytes (`ALMENA_MAX_MESSAGE_BYTES`).
    pub max_message_bytes: usize,
    /// Undelivered messages are dropped after this many seconds (`ALMENA_QUEUE_TTL`).
    pub queue_ttl_secs: u64,
    /// Queued messages per mediation (`ALMENA_QUEUE_MAX_MESSAGES`).
    pub queue_max_messages: usize,
    /// Recipient DIDs per mediation (`ALMENA_MAX_RECIPIENT_DIDS`).
    pub max_recipient_dids: usize,
    /// `POST /didcomm` requests per minute per client IP; 0 turns the limit
    /// off (`ALMENA_RATE_LIMIT`).
    pub rate_limit: u64,
    /// Header holding the client IP when the node runs behind a reverse
    /// proxy, e.g. `x-forwarded-for` (`ALMENA_CLIENT_IP_HEADER`). Its last
    /// value is used: the one the proxy added. Unset: the peer address.
    pub client_ip_header: Option<String>,
    /// Relay `forward`s for recipients mediated elsewhere to their node, and
    /// resolve other nodes' `did:web` over HTTPS (`ALMENA_FEDERATION`).
    pub federation: bool,
    /// Let outbound requests use plain HTTP and private addresses — local
    /// multi-node testing only (`ALMENA_OUTBOUND_ALLOW_INSECURE`).
    pub outbound_allow_insecure: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            log_format: LogFormat::Pretty,
            public_url: "http://localhost:8080".to_owned(),
            keys_path: PathBuf::from("data/keys.json"),
            redis_url: "redis://localhost:6379".to_owned(),
            max_message_bytes: 1024 * 1024,
            queue_ttl_secs: 30 * 24 * 3600,
            queue_max_messages: 10_000,
            max_recipient_dids: 100,
            rate_limit: 60,
            client_ip_header: None,
            federation: true,
            outbound_allow_insecure: false,
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Builds the configuration from any key lookup, so tests don't have to
    /// touch the process environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let default = Self::default();

        let host = match lookup("ALMENA_HOST") {
            Some(v) => v
                .parse()
                .with_context(|| format!("invalid ALMENA_HOST: {v}"))?,
            None => default.bind.ip(),
        };
        let port = match lookup("ALMENA_PORT") {
            Some(v) => v
                .parse()
                .with_context(|| format!("invalid ALMENA_PORT: {v}"))?,
            None => default.bind.port(),
        };
        let log_format = match lookup("ALMENA_LOG_FORMAT").as_deref() {
            None | Some("pretty") => LogFormat::Pretty,
            Some("json") => LogFormat::Json,
            Some(other) => {
                anyhow::bail!("invalid ALMENA_LOG_FORMAT: {other} (expected pretty or json)")
            }
        };

        let public_url = lookup("ALMENA_PUBLIC_URL").unwrap_or(default.public_url);
        let public_url = public_url.trim_end_matches('/').to_owned();
        almena_didcomm::did::web::did_from_origin(&public_url)
            .with_context(|| format!("invalid ALMENA_PUBLIC_URL: {public_url}"))?;
        let client_ip_header = match lookup("ALMENA_CLIENT_IP_HEADER") {
            Some(v) if v.trim().is_empty() => None,
            Some(v) => {
                let name = v.trim().to_ascii_lowercase();
                axum::http::HeaderName::from_str(&name)
                    .with_context(|| format!("invalid ALMENA_CLIENT_IP_HEADER: {v}"))?;
                Some(name)
            }
            None => None,
        };

        Ok(Self {
            bind: SocketAddr::new(host, port),
            log_format,
            public_url,
            keys_path: lookup("ALMENA_KEYS_PATH").map_or(default.keys_path, PathBuf::from),
            redis_url: lookup("ALMENA_REDIS_URL").unwrap_or(default.redis_url),
            max_message_bytes: positive(
                &lookup,
                "ALMENA_MAX_MESSAGE_BYTES",
                default.max_message_bytes,
            )?,
            queue_ttl_secs: positive(&lookup, "ALMENA_QUEUE_TTL", default.queue_ttl_secs)?,
            queue_max_messages: positive(
                &lookup,
                "ALMENA_QUEUE_MAX_MESSAGES",
                default.queue_max_messages,
            )?,
            max_recipient_dids: positive(
                &lookup,
                "ALMENA_MAX_RECIPIENT_DIDS",
                default.max_recipient_dids,
            )?,
            rate_limit: match lookup("ALMENA_RATE_LIMIT") {
                Some(v) => v
                    .parse()
                    .with_context(|| format!("invalid ALMENA_RATE_LIMIT: {v}"))?,
                None => default.rate_limit,
            },
            client_ip_header,
            federation: boolean(&lookup, "ALMENA_FEDERATION", default.federation)?,
            outbound_allow_insecure: boolean(
                &lookup,
                "ALMENA_OUTBOUND_ALLOW_INSECURE",
                default.outbound_allow_insecure,
            )?,
        })
    }
}

/// `true`/`false` (also `1`/`0`), or `default` when unset.
fn boolean(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: bool) -> Result<bool> {
    match lookup(key).as_deref().map(str::trim) {
        None => Ok(default),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(other) => anyhow::bail!("invalid {key}: {other} (expected true or false)"),
    }
}

/// A number above zero, or `default` when unset.
fn positive<T>(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: T) -> Result<T>
where
    T: FromStr + PartialOrd + Default,
{
    match lookup(key) {
        Some(v) => v
            .parse()
            .ok()
            .filter(|n: &T| *n > T::default())
            .with_context(|| format!("invalid {key}: {v} (expected a number above zero)")),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn defaults_when_unset() {
        assert_eq!(Config::from_lookup(lookup(&[])).unwrap(), Config::default());
    }

    #[test]
    fn reads_overrides() {
        let config = Config::from_lookup(lookup(&[
            ("ALMENA_HOST", "127.0.0.1"),
            ("ALMENA_PORT", "9000"),
            ("ALMENA_LOG_FORMAT", "json"),
            ("ALMENA_PUBLIC_URL", "https://node.example.com/"),
            ("ALMENA_KEYS_PATH", "/data/keys.json"),
            ("ALMENA_REDIS_URL", "redis://redis:6379"),
            ("ALMENA_MAX_MESSAGE_BYTES", "2048"),
            ("ALMENA_QUEUE_TTL", "60"),
            ("ALMENA_QUEUE_MAX_MESSAGES", "5"),
            ("ALMENA_MAX_RECIPIENT_DIDS", "7"),
            ("ALMENA_RATE_LIMIT", "0"),
            ("ALMENA_CLIENT_IP_HEADER", "X-Forwarded-For"),
            ("ALMENA_FEDERATION", "false"),
            ("ALMENA_OUTBOUND_ALLOW_INSECURE", "1"),
        ]))
        .unwrap();
        assert_eq!(config.bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(config.public_url, "https://node.example.com");
        assert_eq!(config.keys_path, PathBuf::from("/data/keys.json"));
        assert_eq!(config.redis_url, "redis://redis:6379");
        assert_eq!(config.max_message_bytes, 2048);
        assert_eq!(config.queue_ttl_secs, 60);
        assert_eq!(config.queue_max_messages, 5);
        assert_eq!(config.max_recipient_dids, 7);
        assert_eq!(config.rate_limit, 0);
        assert_eq!(config.client_ip_header.as_deref(), Some("x-forwarded-for"));
        assert!(!config.federation);
        assert!(config.outbound_allow_insecure);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Config::from_lookup(lookup(&[("ALMENA_PORT", "nope")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_LOG_FORMAT", "xml")])).is_err());
        assert!(
            Config::from_lookup(lookup(&[("ALMENA_PUBLIC_URL", "https://x.org/node")])).is_err()
        );
        assert!(Config::from_lookup(lookup(&[("ALMENA_MAX_MESSAGE_BYTES", "0")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_QUEUE_TTL", "-1")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_CLIENT_IP_HEADER", "bad header")])).is_err());
    }
}
