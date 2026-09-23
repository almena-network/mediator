//! The DIDComm side of the mediator: unpacks what arrives at `/didcomm`, runs the
//! protocols addressed to the mediator itself, queues `forward` payloads and packs
//! the replies.

pub mod live;
mod mediation;
mod pickup;
pub mod protocols;
mod relay;

use std::sync::Arc;

use almena_didcomm::did::{ChainResolver, DidResolver, LocalResolver, StaticResolver};
use almena_didcomm::message::now;
use almena_didcomm::{Attachment, FORWARD, Message, PackOptions, unpack};
use tokio::sync::mpsc;

use crate::identity::Identity;
use crate::store::{QueueLimits, Queued, Store};
use crate::transport::{Transport, WebResolver};
use live::{LiveHub, Session};
use protocols::Problem;

/// Limits the mediator enforces (docs/didcomm.md §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_message_bytes: usize,
    pub queue: QueueLimits,
    pub max_recipient_dids: usize,
}

/// What the HTTP layer should answer after a message was accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Processed; nothing goes back on this connection.
    Accepted,
    /// Processed; this encrypted reply goes back on this connection
    /// (the sender asked for it with `return_route`).
    Reply(String),
}

/// Why a message was not accepted. None of these can be answered over
/// DIDComm: the envelope did not open, or it was a `forward`, whose sender
/// is anonymous by design.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error(transparent)]
    Unpack(#[from] almena_didcomm::Error),
    #[error("invalid forward: {0}")]
    BadForward(&'static str),
    #[error("the forward's next recipient is not mediated here")]
    UnknownRecipient,
    #[error("the recipient's queue is full")]
    QueueFull,
    #[error("storage: {0:#}")]
    Store(#[from] anyhow::Error),
}

/// What a protocol handler decided.
#[expect(
    clippy::large_enum_variant,
    reason = "returned once per request and consumed at once; boxing buys nothing"
)]
pub(crate) enum Handled {
    Reply(Message),
    Problem(Problem),
    Nothing,
}

pub struct Mediator {
    identity: Identity,
    resolver: ChainResolver,
    store: Arc<dyn Store>,
    limits: Limits,
    live: LiveHub,
    /// Outbound traffic to other mediators; `None` turns federation off.
    transport: Option<Arc<dyn Transport>>,
}

impl Mediator {
    pub fn new(
        identity: Identity,
        store: Arc<dyn Store>,
        limits: Limits,
        transport: Option<Arc<dyn Transport>>,
    ) -> Self {
        // Our own did:web resolves from memory, did:key / did:peer locally,
        // other did:web DIDs over HTTPS when federation is on.
        let mut resolvers: Vec<Arc<dyn DidResolver>> = vec![
            Arc::new(StaticResolver::new([identity.document.clone()])),
            Arc::new(LocalResolver::new()),
        ];
        if let Some(transport) = &transport {
            resolvers.push(Arc::new(WebResolver::new(Arc::clone(transport))));
        }
        Self {
            identity,
            resolver: ChainResolver::new(resolvers),
            store,
            limits,
            live: LiveHub::default(),
            transport,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn store(&self) -> &dyn Store {
        self.store.as_ref()
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub(crate) fn resolver(&self) -> &ChainResolver {
        &self.resolver
    }

    pub(crate) fn transport(&self) -> Option<&Arc<dyn Transport>> {
        self.transport.as_ref()
    }

    pub(crate) fn live(&self) -> &LiveHub {
        &self.live
    }

    /// Starts a live-capable session (a WebSocket connection). Its
    /// connection task reads live pushes from the receiver and passes each to
    /// [`Mediator::live_delivery`].
    pub fn open_session(&self) -> (Session, mpsc::Receiver<Queued>) {
        self.live.open()
    }

    /// Ends a session: no more live pushes for it.
    pub fn close_session(&self, session: &mut Session) {
        self.live.disable(session);
    }

    /// Packs a live push as a Message Pickup `delivery` for the session's
    /// mediation. The message stays queued until acknowledged.
    pub async fn live_delivery(&self, session: &Session, queued: Queued) -> Option<String> {
        let mediation = session.live_mediation()?;
        let delivery = Message::new(protocols::DELIVERY, serde_json::json!({}))
            .attachment(Attachment::base64(queued.message.as_bytes()).with_id(queued.id));
        self.pack_reply(delivery, mediation).await
    }

    /// Handles one envelope. `session` is the live-capable connection it
    /// came on (a WebSocket), or `None` for HTTP.
    pub async fn receive(
        &self,
        packed: &str,
        mut session: Option<&mut Session>,
    ) -> Result<Outcome, ReceiveError> {
        let (message, meta) = unpack(packed, &self.resolver, self.identity.secrets()).await?;
        if !meta.encrypted {
            return Err(almena_didcomm::Error::Malformed(
                "the mediator accepts encrypted messages only".into(),
            )
            .into());
        }
        tracing::debug!(id = %message.id, r#type = %message.type_, authenticated = meta.authenticated, "received");
        // Unpack guarantees `from` is the authcrypt sender when authenticated.
        let requester = message.from.as_deref().filter(|_| meta.authenticated);

        let handled = if message.is_expired_at(now()) {
            Handled::Problem(Problem::Expired)
        } else {
            let t = message.type_.as_str();
            match t {
                FORWARD => {
                    mediation::forward(self, &message).await?;
                    Handled::Nothing
                }
                protocols::PING => {
                    protocols::trust_ping(&message).map_or(Handled::Nothing, Handled::Reply)
                }
                protocols::QUERIES => {
                    match protocols::discover_features(&message, self.limits.max_message_bytes) {
                        Ok(disclose) => Handled::Reply(disclose),
                        Err(problem) => Handled::Problem(problem),
                    }
                }
                protocols::PROBLEM_REPORT => {
                    tracing::warn!(
                        code = ?message.body.get("code"),
                        comment = ?message.body.get("comment"),
                        pthid = ?message.pthid,
                        "problem report received"
                    );
                    Handled::Nothing
                }
                _ if t.starts_with(protocols::COORDINATE_MEDIATION)
                    || t.starts_with(protocols::PICKUP) =>
                {
                    match requester {
                        None => Handled::Problem(Problem::Unauthenticated),
                        Some(requester) if t.starts_with(protocols::PICKUP) => {
                            pickup::handle(self, requester, &message, session.as_deref_mut())
                                .await?
                        }
                        Some(requester) => mediation::handle(self, requester, &message).await?,
                    }
                }
                _ => Handled::Problem(Problem::UnsupportedType),
            }
        };

        let reply = match handled {
            Handled::Reply(reply) => reply,
            Handled::Problem(problem) => problem.report(&message),
            Handled::Nothing => return Ok(Outcome::Accepted),
        };
        Ok(self.route_back(&message, reply, session.is_some()).await)
    }

    /// Packs `reply` for the sender of `request` if it can travel back on the
    /// same connection: the request must say who sent it (`from`), and ask
    /// for `return_route: "all"` unless the connection is a WebSocket, where
    /// it is implied. Otherwise the reply is dropped (docs/didcomm.md §5).
    async fn route_back(&self, request: &Message, reply: Message, websocket: bool) -> Outcome {
        let Some(sender) = request.from.as_deref() else {
            tracing::debug!(id = %request.id, "anonymous sender, reply dropped");
            return Outcome::Accepted;
        };
        let asked = request
            .extra_headers
            .get("return_route")
            .and_then(|v| v.as_str())
            == Some("all");
        if !websocket && !asked {
            tracing::debug!(id = %request.id, "no return_route, reply dropped");
            return Outcome::Accepted;
        }
        self.pack_reply(reply, sender)
            .await
            .map_or(Outcome::Accepted, Outcome::Reply)
    }

    /// Authcrypts `reply` from the mediator to `recipient`, never wrapped for the
    /// recipient's mediators: it goes back on the connection it came from.
    async fn pack_reply(&self, reply: Message, recipient: &str) -> Option<String> {
        let sender = recipient;
        let reply = reply.from(&self.identity.did).to([sender]);
        // The reply goes back on this connection: never wrap it for the
        // sender's mediators.
        let options = PackOptions {
            forward: false,
            ..PackOptions::default()
        };
        match reply
            .pack_encrypted(
                sender,
                Some(&self.identity.did),
                None,
                &self.resolver,
                self.identity.secrets(),
                options,
            )
            .await
        {
            Ok(packed) => Some(packed.message),
            Err(err) => {
                tracing::warn!(%sender, error = %err, "could not pack reply");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use almena_didcomm::Curve;
    use serde_json::json;

    use super::*;
    use crate::testing::Wallet;

    fn mediator() -> Mediator {
        crate::testing::mediator()
    }

    fn ping(wallet: &Wallet) -> Message {
        Message::new(protocols::PING, json!({"response_requested": true}))
            .from(&wallet.did)
            .header("return_route", json!("all"))
    }

    #[tokio::test]
    async fn ping_with_return_route_gets_a_response_on_every_curve_the_mediator_has() {
        let mediator = mediator();
        for curve in [Curve::X25519, Curve::P384] {
            let wallet = Wallet::new(curve);
            let request = ping(&wallet);
            let packed = wallet
                .send(mediator.identity(), request.clone(), false)
                .await;
            let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
                panic!("expected a reply");
            };
            let response = wallet.open(mediator.identity(), &reply).await;
            assert_eq!(response.type_, protocols::PING_RESPONSE);
            assert_eq!(response.thid.as_deref(), Some(request.id.as_str()));
        }
    }

    #[tokio::test]
    async fn anoncrypted_ping_from_a_known_did_is_answered() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let packed = wallet.send(mediator.identity(), ping(&wallet), true).await;
        assert!(matches!(
            mediator.receive(&packed, None).await.unwrap(),
            Outcome::Reply(_)
        ));
    }

    #[tokio::test]
    async fn without_return_route_nothing_comes_back() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let mut request = ping(&wallet);
        request.extra_headers.remove("return_route");
        let packed = wallet.send(mediator.identity(), request, false).await;
        assert_eq!(
            mediator.receive(&packed, None).await.unwrap(),
            Outcome::Accepted
        );
    }

    #[tokio::test]
    async fn unknown_types_get_a_problem_report() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let request = Message::new("https://example.com/chess/1.0/move", json!({}))
            .from(&wallet.did)
            .header("return_route", json!("all"));
        let packed = wallet
            .send(mediator.identity(), request.clone(), false)
            .await;
        let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
            panic!("expected a problem report");
        };
        let report = wallet.open(mediator.identity(), &reply).await;
        assert_eq!(report.type_, protocols::PROBLEM_REPORT);
        assert_eq!(report.body["code"], "e.m.msg.unsupported-type");
        assert_eq!(report.pthid.as_deref(), Some(request.id.as_str()));
    }

    #[tokio::test]
    async fn expired_messages_get_a_problem_report() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let mut request = ping(&wallet);
        request.expires_time = Some(1);
        let packed = wallet.send(mediator.identity(), request, false).await;
        let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
            panic!("expected a problem report");
        };
        assert_eq!(
            wallet.open(mediator.identity(), &reply).await.body["code"],
            "e.m.req.time.expired"
        );
    }

    #[tokio::test]
    async fn plaintext_is_refused() {
        let (mediator, wallet) = (mediator(), Wallet::new(Curve::X25519));
        let plain = ping(&wallet)
            .to([mediator.identity().did.as_str()])
            .pack_plaintext()
            .unwrap();
        assert!(matches!(
            mediator.receive(&plain, None).await,
            Err(ReceiveError::Unpack(_))
        ));
    }

    #[tokio::test]
    async fn envelopes_for_someone_else_are_refused() {
        let mediator = mediator();
        let (wallet, other) = (Wallet::new(Curve::X25519), Wallet::new(Curve::X25519));
        let packed = ping(&wallet)
            .to([other.did.as_str()])
            .pack_encrypted(
                &other.did,
                Some(&wallet.did),
                None,
                &LocalResolver::new(),
                &wallet.secrets,
                PackOptions::default(),
            )
            .await
            .unwrap()
            .message;
        assert!(matches!(
            mediator.receive(&packed, None).await,
            Err(ReceiveError::Unpack(almena_didcomm::Error::SecretNotFound(
                _
            )))
        ));
    }

    // ---- Coordinate Mediation, forward and Message Pickup ----

    use almena_didcomm::{Attachment, b64};

    /// Grants mediation to `wallet` and registers its own DID as a recipient.
    async fn mediate(mediator: &Mediator, wallet: &Wallet) {
        let grant = wallet
            .request(mediator, protocols::MEDIATE_REQUEST, json!({}))
            .await;
        assert_eq!(grant.type_, protocols::MEDIATE_GRANT);
        assert_eq!(grant.body["routing_did"], json!([mediator.identity().did]));
        let response = wallet
            .request(
                mediator,
                protocols::RECIPIENT_UPDATE,
                json!({"updates": [{"recipient_did": wallet.did, "action": "add"}]}),
            )
            .await;
        assert_eq!(response.body["updated"][0]["result"], "success");
    }

    /// Alice → (forward via the mediator) → Bob, as Alice's wallet would send it.
    async fn send_via_mediator(
        mediator: &Mediator,
        alice: &Wallet,
        bob: &Wallet,
        text: &str,
    ) -> Result<Outcome, ReceiveError> {
        let packed = Message::new(
            "https://example.com/chat/1.0/message",
            json!({ "text": text }),
        )
        .from(&alice.did)
        .to([bob.did.as_str()])
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &Wallet::resolver(mediator.identity()),
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
        assert!(packed.forwarded, "Bob's DID routes through the mediator");
        assert_eq!(
            packed.service_uri.as_deref(),
            Some("https://mediator.example.com/didcomm")
        );
        mediator.receive(&packed.message, None).await
    }

    #[tokio::test]
    async fn a_message_travels_from_alice_to_bob_through_the_mediator() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;

        assert_eq!(
            send_via_mediator(&mediator, &alice, &bob, "hi Bob")
                .await
                .unwrap(),
            Outcome::Accepted
        );

        let status = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(status.type_, protocols::STATUS);
        assert_eq!(status.body["message_count"], 1);
        assert_eq!(status.body["live_delivery"], false);

        let delivery = bob
            .request(&mediator, protocols::DELIVERY_REQUEST, json!({"limit": 10}))
            .await;
        assert_eq!(delivery.type_, protocols::DELIVERY);
        let attachments = delivery.attachments.unwrap();
        assert_eq!(attachments.len(), 1);
        let packed =
            String::from_utf8(b64::decode(attachments[0].data.base64.as_deref().unwrap()).unwrap())
                .unwrap();
        let (message, meta) = unpack(
            &packed,
            &Wallet::resolver(mediator.identity()),
            &bob.secrets,
        )
        .await
        .unwrap();
        assert!(meta.authenticated);
        assert_eq!(message.from.as_deref(), Some(alice.did.as_str()));
        assert_eq!(message.body["text"], "hi Bob");

        // Delivered messages stay until acknowledged.
        let again = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(again.body["message_count"], 1);
        let id = attachments[0].id.clone().unwrap();
        let after = bob
            .request(
                &mediator,
                protocols::MESSAGES_RECEIVED,
                json!({"message_id_list": [id]}),
            )
            .await;
        assert_eq!(after.type_, protocols::STATUS);
        assert_eq!(after.body["message_count"], 0);

        // With an empty queue, a delivery request answers with a status.
        let empty = bob
            .request(&mediator, protocols::DELIVERY_REQUEST, json!({"limit": 10}))
            .await;
        assert_eq!(empty.type_, protocols::STATUS);
    }

    #[tokio::test]
    async fn pickup_filters_by_recipient_did() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let bob_other = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(
            &mediator,
            protocols::RECIPIENT_UPDATE,
            json!({"updates": [{"recipient_did": bob_other.did, "action": "add"}]}),
        )
        .await;
        send_via_mediator(&mediator, &alice, &bob, "one")
            .await
            .unwrap();
        send_via_mediator(&mediator, &alice, &bob_other, "two")
            .await
            .unwrap();

        let all = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(all.body["message_count"], 2);
        let one = bob
            .request(
                &mediator,
                protocols::STATUS_REQUEST,
                json!({"recipient_did": bob_other.did}),
            )
            .await;
        assert_eq!(one.body["message_count"], 1);
        assert_eq!(one.body["recipient_did"], bob_other.did);

        let stranger = Wallet::new(Curve::X25519);
        let report = bob
            .request(
                &mediator,
                protocols::DELIVERY_REQUEST,
                json!({"limit": 1, "recipient_did": stranger.did}),
            )
            .await;
        assert_eq!(report.body["code"], "e.m.msg.unknown-recipient");
    }

    #[tokio::test]
    async fn recipient_updates_report_each_result() {
        let mediator = mediator();
        let (bob, carol) = (Wallet::new(Curve::X25519), Wallet::new(Curve::X25519));
        mediate(&mediator, &bob).await;
        mediate(&mediator, &carol).await;
        let response = bob
            .request(
                &mediator,
                protocols::RECIPIENT_UPDATE,
                json!({"updates": [
                    {"recipient_did": bob.did, "action": "add"},
                    {"recipient_did": carol.did, "action": "add"},
                    {"recipient_did": "did:example:new", "action": "add"},
                    {"recipient_did": "did:example:x#key-1", "action": "add"},
                    {"recipient_did": "did:example:y", "action": "remove"},
                    {"recipient_did": "did:example:new", "action": "rename"}
                ]}),
            )
            .await;
        let results: Vec<_> = response.body["updated"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["result"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            results,
            [
                "no_change",
                "client_error",
                "success",
                "client_error",
                "no_change",
                "client_error"
            ]
        );
    }

    #[tokio::test]
    async fn recipient_limit_is_enforced() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let updates: Vec<_> = (0..crate::testing::LIMITS.max_recipient_dids)
            .map(|i| json!({"recipient_did": format!("did:example:{i}"), "action": "add"}))
            .collect();
        let response = bob
            .request(
                &mediator,
                protocols::RECIPIENT_UPDATE,
                json!({ "updates": updates }),
            )
            .await;
        // One slot was already taken by Bob's own DID.
        assert_eq!(
            response.body["updated"].as_array().unwrap().last().unwrap()["result"],
            "client_error"
        );
    }

    #[tokio::test]
    async fn recipient_query_paginates() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        bob.request(
            &mediator,
            protocols::RECIPIENT_UPDATE,
            json!({"updates": [{"recipient_did": "did:example:a", "action": "add"}, {"recipient_did": "did:example:b", "action": "add"}]}),
        )
        .await;
        let all = bob
            .request(&mediator, protocols::RECIPIENT_QUERY, json!({}))
            .await;
        assert_eq!(all.body["dids"].as_array().unwrap().len(), 3);
        assert!(all.body.get("pagination").is_none());

        let page = bob
            .request(
                &mediator,
                protocols::RECIPIENT_QUERY,
                json!({"paginate": {"limit": 1, "offset": 1}}),
            )
            .await;
        assert_eq!(
            page.body["dids"],
            json!([{"recipient_did": "did:example:b"}])
        );
        assert_eq!(
            page.body["pagination"],
            json!({"count": 1, "offset": 1, "remaining": 1})
        );
    }

    #[tokio::test]
    async fn mediation_and_pickup_need_an_authenticated_sender() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        let request = Message::new(protocols::MEDIATE_REQUEST, json!({}))
            .from(&bob.did)
            .header("return_route", json!("all"));
        let packed = bob.send(mediator.identity(), request, true).await;
        let Outcome::Reply(reply) = mediator.receive(&packed, None).await.unwrap() else {
            panic!("expected a problem report");
        };
        let report = bob.open(mediator.identity(), &reply).await;
        assert_eq!(report.body["code"], "e.m.trust.unauthenticated");
        assert!(!mediator.store().has_mediation(&bob.did).await.unwrap());
    }

    #[tokio::test]
    async fn pickup_without_mediation_is_refused() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        let report = bob
            .request(&mediator, protocols::STATUS_REQUEST, json!({}))
            .await;
        assert_eq!(report.body["code"], "e.m.req.no-mediation");
    }

    #[tokio::test]
    async fn live_mode_is_refused_over_http() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let on = bob
            .request(
                &mediator,
                protocols::LIVE_DELIVERY_CHANGE,
                json!({"live_delivery": true}),
            )
            .await;
        assert_eq!(on.body["code"], "e.m.live-mode-not-supported");
        let off = bob
            .request(
                &mediator,
                protocols::LIVE_DELIVERY_CHANGE,
                json!({"live_delivery": false}),
            )
            .await;
        assert_eq!(off.type_, protocols::STATUS);
    }

    #[tokio::test]
    async fn a_full_queue_refuses_more_forwards() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        for i in 0..crate::testing::LIMITS.queue.max_messages {
            send_via_mediator(&mediator, &alice, &bob, &i.to_string())
                .await
                .unwrap();
        }
        let err = send_via_mediator(&mediator, &alice, &bob, "one too many")
            .await
            .unwrap_err();
        assert!(matches!(err, ReceiveError::QueueFull));
    }

    #[tokio::test]
    async fn forwards_for_unknown_recipients_are_refused() {
        let mediator = mediator();
        let bob = Wallet::mediated_by(&mediator.identity().did);
        let alice = Wallet::new(Curve::X25519);
        let err = send_via_mediator(&mediator, &alice, &bob, "hi")
            .await
            .unwrap_err();
        assert!(matches!(err, ReceiveError::UnknownRecipient));
    }

    #[tokio::test]
    async fn forwards_must_carry_encrypted_messages() {
        let mediator = mediator();
        let bob = Wallet::new(Curve::X25519);
        mediate(&mediator, &bob).await;
        let forward = Message::new(almena_didcomm::FORWARD, json!({"next": bob.did}))
            .attachment(Attachment::json(json!({"not": "a jwe"})));
        let packed = bob.send(mediator.identity(), forward, true).await;
        let err = mediator.receive(&packed, None).await.unwrap_err();
        assert!(matches!(err, ReceiveError::BadForward(_)));
        assert_eq!(
            mediator
                .store()
                .summary(&bob.did, None, now(), 3600)
                .await
                .unwrap()
                .count,
            0
        );
    }

    // ---- Federation ----

    use crate::testing::{InProcess, mediator_at};
    use almena_didcomm::did::{
        ChainResolver as Chain, LocalResolver as Local, StaticResolver as Static,
    };

    /// Alice hands a message for Bob (mediated at B) to her own mediator A,
    /// which relays it to B.
    #[tokio::test]
    async fn a_mediator_relays_forwards_to_the_recipients_mediator() {
        let net = Arc::new(InProcess::default());
        let a = mediator_at(
            "https://a.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        let b = mediator_at(
            "https://b.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        net.add("https://a.example", &a);
        net.add("https://b.example", &b);

        let bob = Wallet::mediated_by(&b.identity().did);
        mediate(&b, &bob).await;
        let alice = Wallet::new(Curve::X25519);
        let resolver = Chain::new(vec![
            Arc::new(Static::new([
                a.identity().document.clone(),
                b.identity().document.clone(),
            ])),
            Arc::new(Local::new()),
        ]);

        // What Alice's wallet would send B directly...
        let for_b = Message::new(
            "https://example.com/chat/1.0/message",
            json!({"text": "via A"}),
        )
        .from(&alice.did)
        .to([bob.did.as_str()])
        .pack_encrypted(
            &bob.did,
            Some(&alice.did),
            None,
            &resolver,
            &alice.secrets,
            PackOptions::default(),
        )
        .await
        .unwrap();
        assert!(for_b.forwarded);
        // ...handed to A instead, in a forward whose next is B.
        let envelope: serde_json::Value = serde_json::from_str(&for_b.message).unwrap();
        let to_a = Message::new(FORWARD, json!({"next": b.identity().did}))
            .to([a.identity().did.as_str()])
            .attachment(Attachment::json(envelope))
            .pack_encrypted(
                &a.identity().did,
                None,
                None,
                &resolver,
                &alice.secrets,
                PackOptions {
                    forward: false,
                    ..PackOptions::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            a.receive(&to_a.message, None).await.unwrap(),
            Outcome::Accepted
        );
        let status = bob.request(&b, protocols::STATUS_REQUEST, json!({})).await;
        assert_eq!(status.body["message_count"], 1);
    }

    #[tokio::test]
    async fn without_federation_foreign_recipients_are_unknown() {
        let net = Arc::new(InProcess::default());
        let a = mediator_at("https://a.example", None);
        let b = mediator_at(
            "https://b.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        net.add("https://b.example", &b);
        let bob = Wallet::mediated_by(&b.identity().did);
        mediate(&b, &bob).await;
        let forward = Message::new(FORWARD, json!({"next": b.identity().did})).attachment(
            Attachment::json(serde_json::from_str(&some_jwe(&bob).await).unwrap()),
        );
        let packed = bob.send(a.identity(), forward, true).await;
        assert!(matches!(
            a.receive(&packed, None).await,
            Err(ReceiveError::UnknownRecipient)
        ));
    }

    #[tokio::test]
    async fn a_route_back_to_this_mediator_is_not_followed() {
        let net = Arc::new(InProcess::default());
        let a = mediator_at(
            "https://a.example",
            Some(net.clone() as Arc<dyn crate::transport::Transport>),
        );
        net.add("https://a.example", &a);
        // Carol names A as her mediator but never registered.
        let carol = Wallet::mediated_by(&a.identity().did);
        let forward = Message::new(FORWARD, json!({"next": carol.did})).attachment(
            Attachment::json(serde_json::from_str(&some_jwe(&carol).await).unwrap()),
        );
        let packed = carol.send(a.identity(), forward, true).await;
        assert!(matches!(
            a.receive(&packed, None).await,
            Err(ReceiveError::UnknownRecipient)
        ));
    }

    /// Any encrypted message for `wallet`.
    async fn some_jwe(wallet: &Wallet) -> String {
        Message::new("t", json!({}))
            .to([wallet.did.as_str()])
            .pack_encrypted(
                &wallet.did,
                None,
                None,
                &Local::new(),
                &wallet.secrets,
                PackOptions {
                    forward: false,
                    ..PackOptions::default()
                },
            )
            .await
            .unwrap()
            .message
    }
}
