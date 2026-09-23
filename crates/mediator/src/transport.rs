//! Outbound traffic to other mediators: fetching `did:web` documents and posting
//! DIDComm messages.
//!
//! Every URL here comes from a DID document, i.e. from strangers, so the HTTP
//! client guards against SSRF: HTTPS only, no IP-literal hosts, and a DNS
//! resolver that drops private, loopback and link-local addresses — checked
//! at connect time, so DNS rebinding cannot slip past it. Redirects are
//! followed only when temporary (`307`), as the spec asks.
//! `ALMENA_OUTBOUND_ALLOW_INSECURE` lifts all of this for local testing.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use almena_didcomm::did::web::document_url;
use almena_didcomm::did::{DidDocument, DidResolver};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// What the mediator needs from the network.
#[async_trait]
pub trait Transport: Send + Sync {
    /// GETs a JSON document (a `did:web` DID document).
    async fn get_json(&self, url: &str) -> Result<serde_json::Value>;
    /// POSTs one DIDComm encrypted message; fails unless the answer is 2xx.
    async fn post_didcomm(&self, url: &str, message: &str) -> Result<()>;
}

/// [`Transport`] over HTTPS.
pub struct HttpTransport {
    client: reqwest::Client,
    allow_insecure: bool,
}

impl HttpTransport {
    pub fn new(allow_insecure: bool) -> Result<Self> {
        // reqwest is built without a default crypto provider; rustls uses ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let redirect = reqwest::redirect::Policy::custom(|attempt| {
            if attempt.status() == reqwest::StatusCode::TEMPORARY_REDIRECT
                && attempt.previous().len() < 3
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        });
        let mut builder = reqwest::Client::builder()
            .user_agent(format!("almena-mediator/{}", crate::VERSION))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(redirect);
        if !allow_insecure {
            builder = builder.https_only(true).dns_resolver(PublicOnlyResolver);
        }
        Ok(Self {
            client: builder.build().context("building the HTTP client")?,
            allow_insecure,
        })
    }

    fn check(&self, url: &str) -> Result<reqwest::Url> {
        let url = reqwest::Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
        if self.allow_insecure {
            ensure!(
                matches!(url.scheme(), "https" | "http"),
                "unsupported scheme in {url}"
            );
            return Ok(url);
        }
        ensure!(
            url.scheme() == "https",
            "only https URLs are allowed: {url}"
        );
        match url.host() {
            Some(url::Host::Domain(_)) => Ok(url),
            Some(_) => bail!("IP-literal hosts are not allowed: {url}"),
            None => bail!("URL without host: {url}"),
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn get_json(&self, url: &str) -> Result<serde_json::Value> {
        let url = self.check(url)?;
        let response = self
            .client
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?;
        response
            .json()
            .await
            .with_context(|| format!("reading JSON from {url}"))
    }

    async fn post_didcomm(&self, url: &str, message: &str) -> Result<()> {
        let url = self.check(url)?;
        let response = self
            .client
            .post(url.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/didcomm-encrypted+json",
            )
            .body(message.to_owned())
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "{url} answered {}",
            response.status()
        );
        Ok(())
    }
}

/// Resolves names like the system does, keeping only public addresses.
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} has no public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Whether `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
                || (a == 198 && (18..20).contains(&b))) // benchmarking
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00 // unique local
                || (first & 0xffc0) == 0xfe80 // link local
                || first == 0x2001 && v6.segments()[1] == 0x0db8) // documentation
        }
    }
}

/// Resolves `did:web` DIDs over a [`Transport`], caching documents for a
/// few minutes.
pub struct WebResolver {
    transport: Arc<dyn Transport>,
    cache: Mutex<HashMap<String, (DidDocument, Instant)>>,
}

impl WebResolver {
    const TTL: Duration = Duration::from_secs(300);
    const CAPACITY: usize = 1_000;

    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, did: &str) -> Option<DidDocument> {
        let cache = self.cache.lock().ok()?;
        cache
            .get(did)
            .filter(|(_, at)| at.elapsed() < Self::TTL)
            .map(|(doc, _)| doc.clone())
    }
}

#[async_trait]
impl DidResolver for WebResolver {
    async fn resolve(&self, did: &str) -> almena_didcomm::Result<DidDocument> {
        use almena_didcomm::Error;
        if !did.starts_with("did:web:") {
            return Err(Error::DidNotFound(did.to_owned()));
        }
        if let Some(doc) = self.cached(did) {
            return Ok(doc);
        }
        let url = document_url(did)?;
        let json = self
            .transport
            .get_json(&url)
            .await
            .map_err(|err| Error::Resolver(format!("{did}: {err:#}")))?;
        let doc = DidDocument::from_json(&json)?;
        if doc.id != did {
            return Err(Error::Resolver(format!(
                "{url} holds the document of {}",
                doc.id
            )));
        }
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= Self::CAPACITY {
                cache.clear();
            }
            cache.insert(did.to_owned(), (doc.clone(), Instant::now()));
        }
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_pass() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn urls_are_checked() {
        let strict = HttpTransport::new(false).unwrap();
        assert!(strict.check("https://mediator.example.com/didcomm").is_ok());
        assert!(strict.check("http://mediator.example.com/didcomm").is_err());
        assert!(strict.check("https://169.254.169.254/latest").is_err());
        assert!(strict.check("https://[::1]/x").is_err());
        let insecure = HttpTransport::new(true).unwrap();
        assert!(insecure.check("http://localhost:8080/didcomm").is_ok());
        assert!(insecure.check("ftp://localhost/x").is_err());
    }

    #[tokio::test]
    async fn the_resolver_refuses_private_names() {
        use std::str::FromStr;
        let err = PublicOnlyResolver
            .resolve(Name::from_str("localhost").unwrap())
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("no public address"));
    }
}
