//! Test helpers: a mediator on the in-memory store, and wallets that talk to it.

use std::sync::Arc;

use almena_didcomm::did::peer::{Purpose, peer2};
use almena_didcomm::did::{ChainResolver, LocalResolver, StaticResolver};
use almena_didcomm::{Curve, InMemorySecrets, Message, PackOptions, SecretKey, unpack};
use serde_json::json;

use crate::dispatch::{Limits, Mediator, Outcome};
use crate::identity::Identity;
use crate::store::{MemoryStore, QueueLimits, Store};

pub const LIMITS: Limits = Limits {
    max_message_bytes: 64 * 1024,
    queue: QueueLimits {
        ttl_secs: 3600,
        max_messages: 5,
    },
    max_recipient_dids: 3,
};

/// A mediator at `https://mediator.example.com` with an empty in-memory store.
pub fn mediator() -> Mediator {
    mediator_on(Arc::new(MemoryStore::new()))
}

/// A mediator at `https://mediator.example.com` on `store`.
pub fn mediator_on(store: Arc<dyn Store>) -> Mediator {
    Mediator::new(
        Identity::ephemeral("https://mediator.example.com").unwrap(),
        store,
        LIMITS,
        None,
    )
}

/// A wallet with a `did:peer:2` identity (Ed25519 signing key, key agreement
/// on the given curve).
pub struct Wallet {
    pub did: String,
    pub secrets: InMemorySecrets,
}

impl Wallet {
    pub fn new(curve: Curve) -> Self {
        Self::with_services(curve, &[])
    }

    /// A wallet whose DID says "reach me through `mediator_did`".
    pub fn mediated_by(mediator_did: &str) -> Self {
        Self::with_services(
            Curve::X25519,
            &[
                json!({"type": "DIDCommMessaging", "serviceEndpoint": {"uri": mediator_did, "accept": ["didcomm/v2"]}}),
            ],
        )
    }

    fn with_services(curve: Curve, services: &[serde_json::Value]) -> Self {
        let signing = SecretKey::generate(Curve::Ed25519).unwrap();
        let agreement = SecretKey::generate(curve).unwrap();
        let did = peer2(
            &[
                (Purpose::Verification, &signing.public_key()),
                (Purpose::Encryption, &agreement.public_key()),
            ],
            services,
        )
        .unwrap();
        let mut secrets = InMemorySecrets::new();
        secrets.insert(format!("{did}#key-1"), signing);
        secrets.insert(format!("{did}#key-2"), agreement);
        Self { did, secrets }
    }

    pub fn resolver(mediator: &Identity) -> ChainResolver {
        ChainResolver::new(vec![
            Arc::new(StaticResolver::new([mediator.document.clone()])),
            Arc::new(LocalResolver::new()),
        ])
    }

    /// Encrypts `message` to the mediator, authcrypt unless `anonymous`.
    pub async fn send(&self, mediator: &Identity, message: Message, anonymous: bool) -> String {
        let from = (!anonymous).then_some(self.did.as_str());
        message
            .to([mediator.did.as_str()])
            .pack_encrypted(
                &mediator.did,
                from,
                None,
                &Self::resolver(mediator),
                &self.secrets,
                PackOptions::default(),
            )
            .await
            .unwrap()
            .message
    }

    /// Opens a reply from the mediator and checks it is authcrypted by the mediator.
    pub async fn open(&self, mediator: &Identity, reply: &str) -> Message {
        let (message, meta) = unpack(reply, &Self::resolver(mediator), &self.secrets)
            .await
            .unwrap();
        assert!(
            meta.authenticated,
            "replies are authcrypted by the mediator"
        );
        assert_eq!(message.from.as_deref(), Some(mediator.did.as_str()));
        message
    }

    /// Sends an authcrypted request with `return_route: "all"` and returns the reply.
    pub async fn request(
        &self,
        mediator: &Mediator,
        type_: &str,
        body: serde_json::Value,
    ) -> Message {
        let message = Message::new(type_, body)
            .from(&self.did)
            .header("return_route", json!("all"));
        let packed = self.send(mediator.identity(), message, false).await;
        match mediator.receive(&packed, None).await.unwrap() {
            Outcome::Reply(reply) => self.open(mediator.identity(), &reply).await,
            Outcome::Accepted => panic!("{type_}: expected a reply"),
        }
    }
}

/// A mediator at `public_url` on its own in-memory store.
pub fn mediator_at(
    public_url: &str,
    transport: Option<Arc<dyn crate::transport::Transport>>,
) -> Arc<Mediator> {
    Arc::new(Mediator::new(
        Identity::ephemeral(public_url).unwrap(),
        Arc::new(MemoryStore::new()),
        LIMITS,
        transport,
    ))
}

/// A [`Transport`](crate::transport::Transport) that talks to mediators in
/// this process, by origin.
#[derive(Default)]
pub struct InProcess {
    mediators: std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<Mediator>>>,
}

impl InProcess {
    pub fn add(&self, origin: &str, mediator: &Arc<Mediator>) {
        self.mediators
            .lock()
            .unwrap()
            .insert(origin.to_owned(), Arc::downgrade(mediator));
    }

    fn find(&self, url: &str) -> anyhow::Result<(String, Arc<Mediator>)> {
        let mediators = self.mediators.lock().unwrap();
        let (origin, mediator) = mediators
            .iter()
            .find(|(origin, _)| url.starts_with(origin.as_str()))
            .ok_or_else(|| anyhow::anyhow!("no mediator at {url}"))?;
        let path = url[origin.len()..].to_owned();
        Ok((
            path,
            mediator
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("mediator gone"))?,
        ))
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for InProcess {
    async fn get_json(&self, url: &str) -> anyhow::Result<serde_json::Value> {
        let (path, mediator) = self.find(url)?;
        anyhow::ensure!(path == "/.well-known/did.json", "not found: {url}");
        Ok(mediator.identity().document.to_json())
    }

    async fn post_didcomm(&self, url: &str, message: &str) -> anyhow::Result<()> {
        let (path, mediator) = self.find(url)?;
        anyhow::ensure!(path == crate::identity::DIDCOMM_PATH, "not found: {url}");
        mediator.receive(message, None).await?;
        Ok(())
    }
}
