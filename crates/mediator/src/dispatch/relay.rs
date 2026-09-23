//! Federation: passing a `forward` payload on to the mediator that mediates its
//! `next` recipient (docs/didcomm.md §7).
//!
//! The payload is routed as a sender would route it: resolve `next`, wrap it
//! for the hops its `DIDCommMessaging` service lists, POST it to the service
//! URI. The first attempt happens before answering; if it fails the payload
//! is retried in the background with backoff. Retries live in memory only:
//! a restart drops them.

use std::sync::Arc;
use std::time::Duration;

use almena_didcomm::did::did_of;
use almena_didcomm::{ContentEncryption, route};

use super::{Mediator, ReceiveError};
use crate::identity::DIDCOMM_PATH;
use crate::transport::Transport;

/// Waits before each retry after the first attempt.
const BACKOFF: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
];

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
        deliver(Arc::clone(transport), uri, routed.message).await;
    }
    Ok(())
}

fn own_endpoints(mediator: &Mediator) -> Vec<String> {
    mediator
        .identity()
        .document
        .didcomm_services()
        .flat_map(|s| s.didcomm_endpoints().unwrap_or_default())
        .map(|e| e.uri)
        .filter(|uri| uri.ends_with(DIDCOMM_PATH))
        .collect()
}

/// First attempt now; on failure, retries in the background.
async fn deliver(transport: Arc<dyn Transport>, uri: String, message: String) {
    match transport.post_didcomm(&uri, &message).await {
        Ok(()) => tracing::debug!(%uri, "forward relayed"),
        Err(err) => {
            tracing::info!(%uri, error = %format!("{err:#}"), "relay failed, will retry");
            tokio::spawn(async move {
                for (attempt, wait) in BACKOFF.iter().enumerate() {
                    tokio::time::sleep(*wait).await;
                    match transport.post_didcomm(&uri, &message).await {
                        Ok(()) => {
                            tracing::debug!(%uri, attempt = attempt + 2, "forward relayed");
                            return;
                        }
                        Err(err) => {
                            tracing::info!(%uri, attempt = attempt + 2, error = %format!("{err:#}"), "relay failed")
                        }
                    }
                }
                tracing::warn!(%uri, "relay abandoned after retries");
            });
        }
    }
}
