use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};

/// Runtime configuration, read from `ALMENA_*` environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Address the HTTP server binds to (`ALMENA_HOST`, `ALMENA_PORT`).
    pub bind: SocketAddr,
    /// Log output format (`ALMENA_LOG_FORMAT`: `pretty` or `json`).
    pub log_format: LogFormat,
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

        Ok(Self {
            bind: SocketAddr::new(host, port),
            log_format,
        })
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
        ]))
        .unwrap();
        assert_eq!(config.bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.log_format, LogFormat::Json);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Config::from_lookup(lookup(&[("ALMENA_PORT", "nope")])).is_err());
        assert!(Config::from_lookup(lookup(&[("ALMENA_LOG_FORMAT", "xml")])).is_err());
    }
}
