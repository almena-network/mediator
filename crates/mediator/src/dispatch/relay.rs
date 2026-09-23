//! Federation: passing a `forward` payload on to the mediator that mediates its
//! `next` recipient (docs/didcomm.md §7).
//!
//! The payload is routed as a sender would route it: resolve `next`, wrap it
//! for the hops its `DIDCommMessaging` service lists, POST it to the service
//! URI. The first attempt happens before answering; if it fails the payload
//! goes to the store and [`retry_due`] tries it again with backoff, so a
//! restart loses nothing.

use std::sync::Arc;
use std::time::Duration;

use almena_didcomm::did::did_of;
use almena_didcomm::message::now;
use almena_didcomm::{ContentEncryption, b64, route};
use sha2::{Digest, Sha256};

use super::{Mediator, ReceiveError};
use crate::identity::DIDCOMM_PATH;
use crate::metrics::{Forward, METRICS, Retry};
use crate::store::{PendingRelay, Store};
use crate::transport::Transport;

/// Seconds before each retry after the first attempt.
const BACKOFF: [u64; 4] = [5, 30, 120, 600];
/// Relays waiting for a retry, at most: a destination that stays down
/// must not fill the store with copies.
const MAX_PENDING: usize = 1000;
/// How long a relay being tried is kept from other workers.
const LEASE_SECS: u64 = 60;
/// Relays tried per round, and how often a round runs.
const BATCH: usize = 16;
const TICK: Duration = Duration::from_secs(1);

pub async fn relay(
    mediator: &Mediator,
    next: &str,
    payloads: Vec<String>,
) -> Result<(), ReceiveError> {
    let Some(transport) = mediator.transport() else {
        return Err(ReceiveError::UnknownRecipient);
    };
    let own = &mediator.identity().did;
    for payload in payloads {
        let routed = route(
            payload,
            next,
            mediator.resolver(),
            ContentEncryption::A256CbcHs512,
        )
        .await
        .map_err(|err| {
            tracing::debug!(%next, error = %err, "cannot route forward");
            ReceiveError::UnknownRecipient
        })?;
        let Some(uri) = routed.service_uri else {
            tracing::debug!(%next, "next has no DIDComm service");
            return Err(ReceiveError::UnknownRecipient);
        };
        // A route that comes back to this mediator means `next` names us as its
        // mediator without having registered: nowhere to deliver.
        let own_endpoint = own_endpoints(mediator);
        if routed.first_hop.as_deref().map(did_of) == Some(own.as_str())
            || own_endpoint.contains(&uri)
        {
            return Err(ReceiveError::UnknownRecipient);
        }
        deliver(mediator.store(), transport.as_ref(), uri, routed.message).await;
    }
    Ok(())
}

pub(super) fn own_endpoints(mediator: &Mediator) -> Vec<String> {
    mediator
        .identity()
        .document
        .didcomm_services()
        .flat_map(|s| s.didcomm_endpoints().unwrap_or_default())
        .map(|e| e.uri)
        .filter(|uri| uri.ends_with(DIDCOMM_PATH))
        .collect()
}

/// First attempt now; on failure, stored for [`retry_due`].
pub(super) async fn deliver(
    store: &dyn Store,
    transport: &dyn Transport,
    uri: String,
    message: String,
) {
    let Err(err) = transport.post_didcomm(&uri, &message).await else {
        tracing::debug!(%uri, "forward relayed");
        METRICS.forward(Forward::Relayed, 1);
        return;
    };
    tracing::info!(%uri, error = %format!("{err:#}"), "relay failed, will retry");
    let relay = PendingRelay {
        id: relay_id(&uri, &message),
        uri,
        message,
        retries: 0,
    };
    match store
        .schedule_relay(&relay, now() + BACKOFF[0], MAX_PENDING)
        .await
    {
        Ok(true) => METRICS.forward(Forward::RelayScheduled, 1),
        Ok(false) => {
            tracing::warn!(uri = %relay.uri, "too many relays waiting, dropped");
            METRICS.forward(Forward::RelayDropped, 1);
        }
        Err(err) => {
            tracing::warn!(uri = %relay.uri, error = %format!("{err:#}"), "could not store relay, dropped");
            METRICS.forward(Forward::RelayDropped, 1);
        }
    }
}

/// The same payload for the same destination is one relay.
fn relay_id(uri: &str, message: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(uri.as_bytes());
    hash.update([0]);
    hash.update(message.as_bytes());
    b64::encode(hash.finalize())
}

/// Tries the relays due by `now` once each; the ones that fail again are
/// rescheduled, or dropped after the last retry.
pub async fn retry_due(
    store: &dyn Store,
    transport: &dyn Transport,
    now: u64,
) -> anyhow::Result<()> {
    for relay in store.due_relays(now, LEASE_SECS, BATCH).await? {
        let attempt = relay.retries + 2;
        match transport.post_didcomm(&relay.uri, &relay.message).await {
            Ok(()) => {
                tracing::debug!(uri = %relay.uri, attempt, "forward relayed");
                METRICS.relay_retry(Retry::Delivered);
                store.finish_relay(&relay.id).await?;
            }
            Err(err) => {
                let next = relay.retries as usize + 1;
                if let Some(wait) = BACKOFF.get(next) {
                    tracing::info!(uri = %relay.uri, attempt, error = %format!("{err:#}"), "relay failed");
                    METRICS.relay_retry(Retry::Rescheduled);
                    let relay = PendingRelay {
                        retries: relay.retries + 1,
                        ..relay
                    };
                    store
                        .schedule_relay(&relay, now + wait, MAX_PENDING)
                        .await?;
                } else {
                    tracing::warn!(uri = %relay.uri, attempt, error = %format!("{err:#}"), "relay abandoned after retries");
                    METRICS.relay_retry(Retry::Abandoned);
                    store.finish_relay(&relay.id).await?;
                }
            }
        }
    }
    Ok(())
}

/// Runs [`retry_due`] every second until the process ends.
pub fn spawn_retries(store: Arc<dyn Store>, transport: Arc<dyn Transport>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(err) = retry_due(store.as_ref(), transport.as_ref(), now()).await {
                tracing::warn!(error = %format!("{err:#}"), "relay retries failed");
            }
        }
    });
}
