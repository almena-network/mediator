//! Push wake-ups (docs/didcomm.md §5).
//!
//! When a message is queued for a mediation that has no live WebSocket
//! session, the devices the wallet registered get a push that carries
//! nothing but "something is waiting" (`{"type": "almena.wake"}`); the app
//! then connects and picks up. At most one push goes out per mediation until
//! the wallet picks up, and never two closer than the minimum interval.
//!
//! The mediator calls FCM and APNs itself (`ALMENA_PUSH_MODE=direct`), with
//! the credentials of the wallet app: only mediators run by the app's
//! publisher can do this.

mod apns;
mod fcm;
mod jwt;

use std::time::Duration;

use almena_didcomm::message::now;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use self::apns::{Apns, ApnsConfig};
pub use self::fcm::Fcm;
use crate::store::Store;

/// The `type` of every push payload. Nothing else is sent.
pub const WAKE: &str = "almena.wake";

/// A push service a device token belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Service {
    Fcm,
    Apns,
}

impl Service {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fcm => "fcm",
            Self::Apns => "apns",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fcm" => Some(Self::Fcm),
            "apns" => Some(Self::Apns),
            _ => None,
        }
    }
}

/// A device registered for wake-ups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub token: String,
    /// `device_platform` of the FCM protocol (e.g. `android`); none for APNs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// What a push service said about one push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Delivered,
    /// The token is no longer valid; it should be forgotten.
    InvalidToken,
}

/// Sends wake-ups.
#[async_trait]
pub trait Pusher: Send + Sync {
    /// The services this pusher can send through.
    fn services(&self) -> &[Service];
    /// Sends one wake-up to `token`.
    async fn wake(&self, service: Service, token: &str) -> Result<Sent>;
}

/// [`Pusher`] that calls FCM and APNs directly.
pub struct DirectPusher {
    fcm: Option<Fcm>,
    apns: Option<Apns>,
    services: Vec<Service>,
}

impl DirectPusher {
    pub fn new(fcm: Option<Fcm>, apns: Option<Apns>) -> Self {
        let services = [
            fcm.as_ref().map(|_| Service::Fcm),
            apns.as_ref().map(|_| Service::Apns),
        ]
        .into_iter()
        .flatten()
        .collect();
        Self {
            fcm,
            apns,
            services,
        }
    }
}

#[async_trait]
impl Pusher for DirectPusher {
    fn services(&self) -> &[Service] {
        &self.services
    }

    async fn wake(&self, service: Service, token: &str) -> Result<Sent> {
        match (service, &self.fcm, &self.apns) {
            (Service::Fcm, Some(fcm), _) => fcm.wake(token).await,
            (Service::Apns, _, Some(apns)) => apns.wake(token).await,
            _ => anyhow::bail!("{} is not configured", service.as_str()),
        }
    }
}

/// Wakes `mediation`'s devices unless a push already went out since the
/// wallet last picked up. The marker of a sent push lasts at most
/// `hold_secs`. Tokens the service rejects are forgotten.
pub async fn wake(
    store: &dyn Store,
    pusher: &dyn Pusher,
    mediation: &str,
    hold_secs: u64,
) -> Result<()> {
    let devices: Vec<_> = store
        .devices(mediation)
        .await?
        .into_iter()
        .filter(|(service, _)| pusher.services().contains(service))
        .collect();
    if devices.is_empty() || !store.claim_push(mediation, now(), hold_secs).await? {
        return Ok(());
    }
    for (service, device) in devices {
        match pusher.wake(service, &device.token).await {
            Ok(Sent::Delivered) => {
                tracing::debug!(%mediation, service = service.as_str(), "push sent");
            }
            Ok(Sent::InvalidToken) => {
                tracing::info!(%mediation, service = service.as_str(), "push token rejected, removed");
                store
                    .remove_device(mediation, service, &device.token)
                    .await?;
            }
            Err(err) => {
                tracing::warn!(%mediation, service = service.as_str(), error = %format!("{err:#}"), "push failed");
            }
        }
    }
    Ok(())
}

/// HTTP client for FCM and APNs (HTTP/2 is negotiated with APNs).
fn http_client() -> Result<reqwest::Client> {
    // reqwest is built without a default crypto provider; rustls uses ring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!("almena-mediator/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .context("building the push HTTP client")
}

/// DER of the PKCS#8 private key in a PEM file's text.
fn pkcs8_der(pem: &str) -> Result<Vec<u8>> {
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use rustls_pki_types::pem::PemObject;
    let key = PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
        .context("expected a PKCS#8 private key (-----BEGIN PRIVATE KEY-----)")?;
    Ok(key.secret_pkcs8_der().to_vec())
}
