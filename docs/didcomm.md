# DIDComm v2.0 in almena-mediator — design

Status: phases 1–4 implemented (2026-09-23): `almena-didcomm`, the mediator skeleton, mediation, and live delivery / invitations / federation. Phase 5 (push) to come.
Specs:

- [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/) — messages, envelopes, routing. **Decided — v2.0** (DIF-ratified) rather than v2.1, which is only Working Group Approved.
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did/) — what a DID, a DID document and DID resolution are. Every DID method used here follows it.

Items marked **decided** were chosen explicitly. Items marked **proposed** are defaults that stand until someone changes them.

## 1. What the mediator is

**Decided — a pure mediator.** Wallets encrypt end to end. The mediator only sees encrypted envelopes: it accepts them, queues them while the recipient is offline, and delivers them when the recipient connects. It never decrypts message content meant for someone else.

The mediator has its own DID and keys, because wallets talk *to the mediator* to manage their mediation (register, pick up messages, ping). Those administrative messages are the only ones the mediator decrypts.

Out of scope for the mediator: message content (Basic Message and any chat protocol is wallet-to-wallet), groups, user directories, a registry of mediators. Push notifications are in scope only as a content-free wake-up signal (see §5).

## 2. Code layout

**Decided — the DIDComm implementation is our own and lives inside this project for now.** It is a Cargo workspace:

```
mediator/
├── Cargo.toml            workspace
├── crates/
│   ├── didcomm/          almena-didcomm  — message format, envelopes, crypto, DID resolution
│   └── mediator/         almena-mediator — the mediator service
├── Dockerfile
└── compose.yml
```

`almena-didcomm` knows nothing about HTTP, Redis or mediation, so the wallet can depend on it (as a git dependency) when it needs to encrypt. If that becomes awkward it is extracted into its own project.

## 3. Message format (`almena-didcomm`)

### Plaintext headers

| Header | Required | Notes |
|---|---|---|
| `id` | yes | Unique; UUID recommended. |
| `type` | yes | Message type URI (PIURI + message name). |
| `from` | for authcrypt | Must match the envelope's `skid`. |
| `to` | no | If present, must contain the envelope's `kid`. |
| `thid`, `pthid` | no | Threading; `thid` defaults to `id`. |
| `created_time`, `expires_time` | no | UTC epoch seconds. The mediator drops expired messages. |
| `body` | yes | Always present, `{}` when empty (v2.0; v2.1 relaxed this). Messages without it are rejected. |
| `attachments` | no | `base64`, `json`, `links`, optional `jws`. |
| `please_ack`, `ack` | no | Mediators must not honour `please_ack` on forwarded messages. |
| `from_prior` | on DID rotation | JWT signed by the prior DID; verified on unpack. |

Media types: `application/didcomm-plain+json`, `application/didcomm-signed+json`, `application/didcomm-encrypted+json`.

### Envelopes and algorithms

What the spec requires:

| | Algorithms | Status |
|---|---|---|
| Key agreement curves | X25519, P-384, P-256 | required |
| | P-521 | optional — implemented (the spec's test vectors use it) |
| Anoncrypt | ECDH-ES+A256KW with A256CBC-HS512 or A256GCM | required / recommended |
| | XC20P | optional — implemented (the spec's test vectors use it) |
| Authcrypt | ECDH-1PU+A256KW with A256CBC-HS512 | required |
| Signatures | verify EdDSA (Ed25519), ES256, ES256K | required to verify all |
| | sign with EdDSA | the mediator's own signing algorithm |

Unpacking enforces the consistency rules between layers: plaintext `from` = `skid` = signer `kid` DID, and `to` contains the recipient `kid`.

Built on RustCrypto primitives (`x25519-dalek`, `ed25519-dalek`, `p256`, `p384`, `p521`, `k256`, `aes-kw`, `aes-gcm`, `chacha20poly1305`, `aes` + `cbc` + `hmac` + `sha2`) — no JOSE or DIDComm library. The Concat KDF is a few lines of our own (the `concat-kdf` crate lags behind `sha2`).

### Implementation notes (phase 1)

- **Service endpoints.** v2.0 requires the `serviceEndpoint` of a `DIDCommMessaging` service to be a list of `{uri, accept, routingKeys}` objects. We write that form; on reading, a single object (the v2.1 form, still common) is accepted and wrapped in a list.
- **Test vectors.** All nine vectors of the spec's Appendix C (3 signed, 6 encrypted) pass, both at the JWS/JWE level and through the full `unpack`. They live in `crates/didcomm/tests/spec/appendix.json`, extracted from the spec with its errata fixed and listed in the file: recipient secrets are written `"kid "` (trailing space); C.1 says `https://…` but the vectors were made from `http://…`; C.3 #4 says P-521 but uses P-256.
- **`apv` is enforced** on decryption: it must be the hash of the recipient kids actually in the envelope.
- **ECDH-1PU** binds the content tag into the KDF (`SuppPubInfo` = keydatalen ‖ len(tag) ‖ tag); ECDH-ES does not, as in RFC 7518 (the spec's prose says otherwise; its vectors agree with RFC 7518).
- **Accepted layerings** on unpack: plaintext, signed, anoncrypt, authcrypt, anoncrypt(signed), authcrypt(signed), anoncrypt(authcrypt), anoncrypt(authcrypt(signed)). The spec forbids emitting the last one, but its own vector C.3 #6 is exactly that, so we accept it and never emit it.
- **Checks on unpack**: authcrypt sender key ∈ sender's `keyAgreement`; signing key ∈ signer's `authentication`; `from` = `skid` DID = signer DID; `to` (if present) contains the DID we decrypted for; `from_prior` signed by an `authentication` key of `iss`, `sub` = `from`, `iss` ≠ `sub`.
- **Packing** picks the first sender `keyAgreement` key we hold a secret for that shares a curve with the recipient's keys, and encrypts to all recipient keys on that curve. Anoncrypt defaults to A256CBC-HS512 (the one every implementation must support). The signing `kid` goes in both the protected and unprotected JWS headers.
- **Forward wrapping** (phase 3): `pack_encrypted` wraps the message in `forward`s for the recipient's routing hops (`PackOptions::forward`, on by default) and returns the transport URI to POST to (`PackedMessage::service_uri`). The first `DIDCommMessaging` endpoint accepting `didcomm/v2` is used; a DID as `uri` means a mediator, whose `keyAgreement` keys go first in the routing keys and whose own endpoint gives the URI. Forwards are anoncrypted and carry the inner message as a `json` attachment. Rewrapping and `delay_milli` are not used.

### DID resolution

DIDs, DID documents and resolution follow [W3C DID](https://www.w3.org/TR/did/).

| Method | Used by | When |
|---|---|---|
| `did:key` | tests, simple wallets | phase 1 — done |
| `did:peer` (numalgo 2 and 4) | wallets (pairwise DIDs) | phase 1 — done |
| `did:web` | mediators | phase 2 (needs HTTP) |

The resolver is a trait so the mediator can add caching and the wallet can plug in its own. `LocalResolver` handles `did:key` and `did:peer`; `StaticResolver` holds fixed documents; `ChainResolver` combines them.

- An Ed25519 `did:key` also lists the X25519 key derived from it under `keyAgreement`, as DIDComm implementations expect.
- `did:peer:2` key ids are `#key-1`, `#key-2`, … in DID order, and services `#service`, `#service-1`, … (the clarified spec). Older services with a string `serviceEndpoint` are read into the v2.0 form.
- A short-form `did:peer:4` resolves only after its long form has gone through the same `LocalResolver`, which keeps the mapping in memory (bounded). The wallet will need to persist it.

The spec examples for `did:key`, `did:peer:2` and `did:peer:4` are unit tests.

## 4. Protocols the mediator implements

| Protocol | PIURI | Messages | Phase |
|---|---|---|---|
| Trust Ping 2.0 | `https://didcomm.org/trust-ping/2.0` | `ping`, `ping-response` | 2 ✅ |
| Discover Features 2.0 | `https://didcomm.org/discover-features/2.0` | `queries`, `disclose` | 2 ✅ |
| Report Problem 2.0 | `https://didcomm.org/report-problem/2.0` | `problem-report` | 2 ✅ |
| `return_route` extension | header `return_route: "all"` | — | 2 ✅ |
| Coordinate Mediation 3.0 | `https://didcomm.org/coordinate-mediation/3.0` | `mediate-request`, `mediate-grant`, `mediate-deny`, `recipient-update`, `recipient-update-response`, `recipient-query`, `recipient` | 3 ✅ |
| Routing 2.0 | `https://didcomm.org/routing/2.0` | `forward` | 3 ✅ |
| Message Pickup 3.0 | `https://didcomm.org/messagepickup/3.0` | `status-request`, `status`, `delivery-request`, `delivery`, `messages-received`, `live-delivery-change` | 3 ✅ (polling), 4 ✅ (live) |
| Out-of-Band 2.0 | `https://didcomm.org/out-of-band/2.0` | `invitation` | 4 ✅ |
| Push Notifications FCM 1.0 | `https://didcomm.org/push-notifications-fcm/1.0` | `set-device-info`, `get-device-info`, `device-info` | 5 |
| Push Notifications APNs 1.0 | `https://didcomm.org/push-notifications-apns/1.0` | `set-device-info`, `get-device-info`, `device-info` | 5 |

The two push protocols come from Aries RFC 0734 (FCM) and RFC 0699 (APNs), written for DIDComm v1; **proposed:** we use them with v2 plaintext headers and otherwise unchanged bodies, so the wallet registers its device token with the same kind of message it uses for everything else.

`return_route` matters because wallets have no public endpoint: replies travel back over the connection the wallet opened.

### How the mediator answers (phase 2)

- **Trust Ping**: `ping-response` in the ping's thread, unless `response_requested` is `false`.
- **Discover Features**: `disclose` with what matches the queries (`*` is a wildcard; unknown feature types match nothing). The mediator discloses its protocols (with roles), the `return_route` header, and the `max_receive_bytes` constraint (= `ALMENA_MAX_MESSAGE_BYTES`, as the spec's transport section suggests). The spec's privacy advice (varying order, spurious entries) is not applied: a mediator's features are public anyway.
- **Report Problem**: received reports are logged; nothing is sent back.
- **Anything else** gets a problem report. Problem reports open a child thread of the trigger (`pthid` = its `thid`) and `ack` it. Codes used:

| Code | When |
|---|---|
| `e.m.msg.unsupported-type` | Message type the mediator does not handle (`args`: the type). |
| `e.m.msg.invalid-body` | Body without the shape its type requires. |
| `e.m.req.time.expired` | `expires_time` already passed. |

Replies follow §5: they need the request's `from` and `return_route: "all"`.

### Mediation (phase 3)

**Decided:** Coordinate Mediation and Message Pickup messages must be **authcrypted**; anything else gets `e.m.trust.unauthenticated`. The mediation is keyed by the authenticated `from`, so nobody can read or acknowledge (delete) another wallet's queue by claiming its DID.

- **mediate-request** is always granted (§9: open with limits) and is idempotent. `mediate-grant` carries `routing_did: [<mediator DID>]`: the wallet puts the mediator's DID as the `uri` of its own `DIDCommMessaging` service. `mediate-deny` is never sent.
- **recipient-update**: `add` / `remove` per DID, answered with `success`, `no_change` or `client_error`. A recipient DID belongs to the first mediation that registers it (`client_error` for others) — the protocol's own open issue: there is no proof of DID ownership yet. DID URLs, non-DIDs and unknown actions are `client_error`; so is going over `ALMENA_MAX_RECIPIENT_DIDS`. Removing a DID keeps its queued messages until they are picked up or expire.
- **recipient-query**: all DIDs, sorted; with `paginate` a page plus `pagination {count, offset, remaining}`.
- **forward**: `next` (a DID or one of its key ids) must be a registered recipient. Each attachment (`json` or `base64`; `links` are refused) must be an encrypted DIDComm message and is queued as is. `please_ack` is never honoured. Forward senders are anonymous, so failures are HTTP statuses, not problem reports: `400` malformed, `404` unknown recipient, `507` queue full, `503` storage down.
- **Pickup** (`status-request`, `delivery-request`, `messages-received`, `live-delivery-change`) needs a granted mediation (`e.m.req.no-mediation`). `recipient_did`, if given, must be one of the mediation's (`e.m.msg.unknown-recipient`). A `delivery` carries up to `min(limit, 100)` messages, oldest first, as `base64` attachments whose `id` is the queue id to acknowledge. Messages stay queued until `messages-received`. `status` reports `message_count`, `total_bytes`, oldest/newest times, `longest_waited_seconds` and `live_delivery: false`. `live_delivery: true` gets `e.m.live-mode-not-supported` over HTTP (live mode comes with WebSockets, phase 4).
- Replies to the mediator's own messages are never wrapped for the wallet's mediators: they go back on the connection.

`examples/smoke.rs` (`task smoke`) plays Alice and Bob against a running mediator: invitation, ping, mediation, a forwarded message, pickup, acknowledgement, and live delivery over a WebSocket.

### Invitation (phase 4)

`GET /oob/invitation` returns the mediator's Out-of-Band 2.0 invitation and its URL form, `<origin>/oob?_oob=<base64url(JSON)>`, for a link or QR code; `GET /oob` is the human-readable page the spec asks that URL to open in a browser. The invitation says `from: <mediator DID>`, `goal_code: request-mediate`, `accept: ["didcomm/v2"]`, with no attachments: the wallet resolves the mediator's DID and sends `mediate-request` (with the invitation `id` as `pthid`). **Decided:** the invitation never changes — its `id` is derived from the mediator's DID and it has no `created_time` — so a printed QR code keeps working.

## 5. Transports

**Decided — the wallet talks to the mediator over three channels:**

| Channel | Used for |
|---|---|
| HTTPS `POST` | Sending messages to the mediator. The base transport and the most interoperable one; always available. |
| WebSocket | Kept open while the app is in the foreground, to receive messages in real time. |
| Push (FCM / APNs) | Waking the app when it is in the background. The notification carries **no message**, only the fact that something is waiting; the app then connects and picks it up. |

### HTTPS

`POST /didcomm` with `Content-Type: application/didcomm-encrypted+json` (parameters and case are ignored).

| Status | When |
|---|---|
| `202` | Accepted; nothing goes back on this connection. |
| `200` | Accepted; the reply (authcrypted by the mediator) is the body, with the same media type. Only when the message has `from` and `return_route: "all"`. |
| `400` | Not a DIDComm encrypted message the mediator can open: bad JSON, not encrypted for the mediator, sender DID or key unresolvable, failed decryption or verification, inconsistent layers. The JSON error says which of these, never more. Plaintext and signed-only messages are refused too. |
| `413` | Larger than `ALMENA_MAX_MESSAGE_BYTES`. |
| `415` | Any other `Content-Type`. |

DIDComm v2.0 says POST is one-way and replies do not come back in the HTTP response. **Decided:** the `return_route` header extension is the one exception, because wallets have no endpoint of their own; without it the mediator sends nothing back. Replies to senders that do not ask for `return_route` are dropped for now: delivering them to the sender's own endpoint is outbound delivery, which comes with federation (phase 4).

Wallets also use it to poll with Message Pickup (`status-request`, `delivery-request`) when they have no WebSocket open, e.g. right after a push wakes them.

### WebSocket

`GET /ws` upgrades; one DIDComm encrypted message per frame (text or binary, up to `ALMENA_MAX_MESSAGE_BYTES`), in both directions. **Decided:** `return_route` is implied on the socket — every reply comes back on it. Messages count against the same per-IP rate limit as `POST /didcomm`; going over it closes the socket (code 1008).

The wallet opens it when it comes to the foreground and sends Pickup `live-delivery-change` (`live_delivery: true`, authcrypted); the answer is a `status` with `live_delivery: true`. From then on, every message queued for that mediation is pushed down the socket as a `delivery` with one attachment whose `id` is the queue id. Messages already queued are not pushed; the wallet fetches them with `delivery-request` as usual. It closes the socket when the app goes to the background; live mode ends with the connection.

**Decided — live messages stay queued until acknowledged.** Message Pickup 3.0 says live messages are delivered "rather than being pushed to the queue". We queue them *and* push them, and they leave the queue only with `messages-received`, so a connection that drops mid-delivery loses nothing (the usual case on mobile). A wallet that acknowledges what it gets live never sees it twice.

A mediation counts as *online* while a WebSocket session has live mode on for it. Sessions are tracked in process (`dispatch/live.rs`); running several mediator instances behind one Redis would need the `live:{M}` pub/sub channel (§8) to fan pushes out — not done yet.

### Push

1. The wallet registers its device token with the push protocol for its platform (§4). A token belongs to one mediation; re-registering replaces it, and an empty token removes it.
2. When a message is queued for a DID that is not online, the mediator sends a push to that DID's devices. The payload is fixed and content-free (e.g. `{"type":"almena.wake"}`): no sender, no recipient DID, no message id, no count.
3. Pushes are coalesced: at most one per mediation until the wallet next picks up (`status-request`, `delivery-request` or a live WebSocket), with a minimum interval between them (`ALMENA_PUSH_MIN_INTERVAL`).
4. On wake-up the wallet connects (HTTPS pickup, or WebSocket if it comes to the foreground) and fetches what is waiting.
5. Tokens that FCM/APNs report as invalid are deleted.

FCM uses a high-priority data message; APNs a background notification (`content-available: 1`). Mobile OSes throttle background wake-ups, so push is a best-effort hint, never the delivery path: messages always stay queued in the mediator until picked up.

**Open — who holds the FCM/APNs credentials.** Sending a push needs the credentials of the app that owns the token (FCM service account, APNs key for the bundle id). Those belong to whoever publishes the wallet app, not to each mediator operator. **Proposed:** a small *push gateway* run by the wallet publisher holds them; mediators send it `{platform, token}` over HTTPS and it forwards the wake-up. Nothing the gateway sees is linked to a DID or to message content. A mediator run by the publisher may call FCM/APNs directly instead (`ALMENA_PUSH_MODE`: `off`, `gateway`, `direct`).

Desktop wallets have no push: they receive only while running (WebSocket) and poll on start.

### Service endpoint and TLS

The mediator's DID document advertises one `DIDCommMessaging` service with the HTTPS and WebSocket URIs and `accept: ["didcomm/v2"]`. Push is not advertised; it is negotiated through the push protocols.

TLS is terminated in front of the mediator (reverse proxy) in production; the mediator itself speaks plain HTTP.

## 6. Mediator identity and keys

**Decided (phase 2):** the mediator's DID is the `did:web` of its public origin, `ALMENA_PUBLIC_URL` (`scheme://host[:port]`, no path): `https://mediator.example.com` → `did:web:mediator.example.com`, `http://localhost:8080` → `did:web:localhost%3A8080`. The mediator serves the document at `/.well-known/did.json`. The same variable gives the DIDComm endpoint, `<origin>/didcomm`. A domain-based DID is stable and lets other mediators find this one without a central registry.

**Decided (phase 2):** three keys, generated on first start and kept in `ALMENA_KEYS_PATH` (default `data/keys.json`; `/data/keys.json` in the container, on the `mediator-data` volume). The file is JSON with the three private JWKs, written with mode `0600`; mounting a file there brings your own keys.

| Key id | Curve | Relationship |
|---|---|---|
| `<did>#key-ed25519` | Ed25519 | `authentication`, `assertionMethod` |
| `<did>#key-x25519` | X25519 | `keyAgreement` |
| `<did>#key-p384` | P-384 | `keyAgreement` |

The document has one `DIDCommMessaging` service, `<did>#didcomm`, with two endpoints, HTTPS first: `{"uri": "<origin>/didcomm", "accept": ["didcomm/v2"]}` and `{"uri": "wss://<host>/ws", "accept": ["didcomm/v2"]}` (`ws://` for an `http` origin).

Wallets whose key agreement is on another curve (e.g. P-256, which the spec deprecates) cannot get authcrypted replies from the mediator.

The mediator resolves its own DID from memory, and `did:key` / `did:peer` locally. Other `did:web` DIDs are resolved over HTTPS when federation is on (§7).

## 7. Federation

**Decided (phase 4):** there is no mediator registry. When the `next` of a `forward` is not a recipient registered here, the mediator routes the payload as a sender would (`almena_didcomm::route`): resolves `next`, wraps the payload for the hops of its `DIDCommMessaging` service (a mediator DID as `uri`, `routingKeys`), and POSTs it to the service URI. `ALMENA_FEDERATION=false` turns this off (such forwards get `404`).

- Other mediators' `did:web` documents are fetched over HTTPS and cached for 5 minutes. This also lets wallets and mediators with `did:web` DIDs talk to this mediator.
- The first POST happens before the mediator answers the forward (`202` either way once routing succeeded). If it fails, it is retried after 5 s, 30 s, 2 min and 10 min, then dropped. **Retries live in memory**: a restart loses them.
- A route that leads back to this mediator (`next` names this mediator as its mediator but never registered) is `404`, not a loop.
- Redirects are followed only when temporary (`307`), as the spec asks.

**Decided — SSRF guard.** Every outbound URL comes from a DID document, i.e. from strangers. The HTTP client only uses `https`, refuses IP-literal hosts, and resolves names through a resolver that drops private, loopback, link-local, CGNAT and documentation addresses — checked when connecting, so DNS rebinding cannot get around it. `ALMENA_OUTBOUND_ALLOW_INSECURE=true` lifts all of this, for running several mediators on one machine only.

Not done: delivering the mediator's own replies to a sender's endpoint when the sender did not ask for `return_route` — replies still travel only on the connection they answer (§5).

## 8. Storage

**Decided — Redis**, as a service in `compose.yml`, with AOF persistence (`appendonly yes`, `appendfsync everysec`) so queues survive restarts.

The mediator refuses to start without its store (`ALMENA_REDIS_URL`, default `redis://localhost:6379`), and `/health` answers `503` while it is unreachable so the container shows as unhealthy. For `task dev`, `task redis` starts the Compose Redis on `127.0.0.1:${ALMENA_REDIS_PORT}`.

**Decided (phase 3):** storage sits behind a `Store` trait (`crates/mediator/src/store/`) with two implementations: Redis, and an in-process one used by the tests and by `ALMENA_REDIS_URL=memory://` (`task dev:memory`, development only: everything is lost on restart). A shared contract test runs against both; the Redis run needs `ALMENA_TEST_REDIS_URL` (`task test:redis`).

**Decided (phase 3):** one queue per **mediation** rather than per recipient DID, so a delivery's attachment ids are unique across all the wallet's DIDs; `recipient_did` filters within it.

| Key (`M` mediation DID, `R` recipient DID) | Type | Holds |
|---|---|---|
| `mediation:{M}` | string | Grant time |
| `mediation:{M}:recipients` | set | Recipient DIDs registered by `M` |
| `recipient:{R}` | string | The mediation that registered `R` |
| `mediation:{M}:queue` | stream | One entry per queued message: recipient and size |
| `mediation:{M}:msg:{id}` | string with TTL | The message itself |
| `rate:{key}:{window}` | counter with TTL | Rate-limit hits |
| `live:{M}` | pub/sub channel | Wakes the WebSocket session of `M` (phase 4) |
| `push:{M}` | hash | Device tokens (platform → token) (phase 5) |
| `push-sent:{M}` | string with TTL | Push coalescing marker (phase 5) |

Bodies live outside the stream so `status` reads only small entries. Registration and enqueueing are Lua scripts, so they are atomic. Expired entries are trimmed on every read and write (`XTRIM MINID`), and bodies expire on their own.

## 9. Access and limits

**Decided — open with limits.** Any wallet may request mediation; limits protect the mediator and can be tightened later (invitation-only or allowlist) without changing the protocol.

Settings (all `ALMENA_*` environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `ALMENA_MAX_MESSAGE_BYTES` | 1048576 (1 MiB) | Larger envelopes get `413`; disclosed as `max_receive_bytes` ✅ |
| `ALMENA_QUEUE_TTL` | 2592000 (30 days) | Seconds; undelivered messages are dropped after this ✅ |
| `ALMENA_QUEUE_MAX_MESSAGES` | 10000 | Per **mediation**; further forwards get `507` ✅ |
| `ALMENA_MAX_RECIPIENT_DIDS` | 100 | Per mediation; further adds get `client_error` ✅ |
| `ALMENA_RATE_LIMIT` | 60 | `POST /didcomm` requests per minute per client IP (fixed window, counted in the store); over it, `429` with `Retry-After`; `0` turns it off ✅ |
| `ALMENA_CLIENT_IP_HEADER` | — | Behind a reverse proxy: the header carrying the client IP (e.g. `x-forwarded-for`); its **last** value is used, the one our proxy added. Unset: the TCP peer address ✅ |
| `ALMENA_PUSH_MODE` | `off` | `off`, `gateway` or `direct` (§5) |
| `ALMENA_PUSH_GATEWAY_URL` | — | Push gateway endpoint, for `gateway` mode |
| `ALMENA_PUSH_MIN_INTERVAL` | 60 s | Minimum time between pushes to one mediation |

## 10. Phases

1. ✅ **`almena-didcomm`** — workspace split; message model; JWK and key types; `did:key` and `did:peer` resolution; JWS sign/verify; anoncrypt and authcrypt; pack/unpack with consistency checks and `from_prior`; spec test vectors.
2. ✅ **Mediator skeleton** — mediator identity and keys, `did:web` document, `POST /didcomm`, Redis in Compose, Trust Ping, Discover Features, Report Problem, `return_route`.
3. ✅ **Mediation** — Coordinate Mediation 3.0, `forward`, Message Pickup 3.0 (polling), limits.
4. ✅ **Live and network** — WebSocket and live delivery, Out-of-Band invitations, forwarding to other mediators.
5. **Push** — FCM and APNs push protocols, token storage, content-free wake-ups with coalescing, push gateway (or direct mode).

Each phase ends with `task check` green and the docs updated.
