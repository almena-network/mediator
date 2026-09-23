# DIDComm v2.1 in almena-node — design

Status: agreed definition, before implementation (2026-09-22).
Specs:

- [DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/) — messages, envelopes, routing.
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did/) — what a DID, a DID document and DID resolution are. Every DID method used here follows it.

Items marked **decided** were chosen explicitly. Items marked **proposed** are defaults that stand until someone changes them.

## 1. What the node is

**Decided — the node is a pure mediator.** Wallets encrypt end to end. The node only sees encrypted envelopes: it accepts them, queues them while the recipient is offline, and delivers them when the recipient connects. It never decrypts message content meant for someone else.

The node has its own DID and keys, because wallets talk *to the node* to manage their mediation (register, pick up messages, ping). Those administrative messages are the only ones the node decrypts.

Out of scope for the node: message content (Basic Message and any chat protocol is wallet-to-wallet), groups, push notifications, user directories, a registry of nodes.

## 2. Code layout

**Decided — the DIDComm implementation is our own and lives inside `node` for now.** `node/` becomes a Cargo workspace:

```
node/
├── Cargo.toml            workspace
├── crates/
│   ├── didcomm/          almena-didcomm — message format, envelopes, crypto, DID resolution
│   └── node/             almena-node    — the mediator service (current code moves here)
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
| `created_time`, `expires_time` | no | UTC epoch seconds. The node drops expired messages. |
| `body` | no | May be absent when empty (v2.1 change). |
| `attachments` | no | `base64`, `json`, `links`, optional `jws`. |
| `please_ack`, `ack` | no | Mediators must not honour `please_ack` on forwarded messages. |
| `from_prior` | on DID rotation | JWT signed by the prior DID; verified on unpack. |

Media types: `application/didcomm-plain+json`, `application/didcomm-signed+json`, `application/didcomm-encrypted+json`.

### Envelopes and algorithms

What the spec requires:

| | Algorithms | Status |
|---|---|---|
| Key agreement curves | X25519, P-384, P-256 | required |
| | P-521 | optional — later |
| Anoncrypt | ECDH-ES+A256KW with A256CBC-HS512 or A256GCM | required / recommended |
| Authcrypt | ECDH-1PU+A256KW with A256CBC-HS512 | required |
| | XC20P | optional — later |
| Signatures | verify EdDSA (Ed25519), ES256, ES256K | required to verify all |
| | sign with EdDSA | the node's own signing algorithm |

Unpacking enforces the consistency rules between layers: plaintext `from` = `skid` = signer `kid` DID, and `to` contains the recipient `kid`.

Built on RustCrypto primitives (`x25519-dalek`, `ed25519-dalek`, `p256`, `p384`, `k256`, `aes-kw`, `aes-gcm`, `aes` + `cbc` + `hmac` + `sha2`, `concat-kdf`) — no JOSE or DIDComm library. The test vectors in the spec's appendix are part of the test suite from the first commit.

### DID resolution

DIDs, DID documents and resolution follow [W3C DID](https://www.w3.org/TR/did/).

| Method | Used by | When |
|---|---|---|
| `did:key` | tests, simple wallets | phase 1 |
| `did:peer` (numalgo 2 and 4) | wallets (pairwise DIDs) | phase 1 |
| `did:web` | nodes | phase 2 (needs HTTP) |

The resolver is a trait so the node can add caching and the wallet can plug in its own.

## 4. Protocols the node implements

| Protocol | PIURI | Messages | Phase |
|---|---|---|---|
| Trust Ping 2.0 | `https://didcomm.org/trust-ping/2.0` | `ping`, `ping-response` | 2 |
| Discover Features 2.0 | `https://didcomm.org/discover-features/2.0` | `queries`, `disclose` | 2 |
| Report Problem 2.0 | `https://didcomm.org/report-problem/2.0` | `problem-report` | 2 |
| `return_route` extension | header `return_route: "all"` | — | 2 |
| Coordinate Mediation 3.0 | `https://didcomm.org/coordinate-mediation/3.0` | `mediate-request`, `mediate-grant`, `mediate-deny`, `recipient-update`, `recipient-update-response`, `recipient-query`, `recipient` | 3 |
| Routing 2.0 | `https://didcomm.org/routing/2.0` | `forward` | 3 |
| Message Pickup 3.0 | `https://didcomm.org/messagepickup/3.0` | `status-request`, `status`, `delivery-request`, `delivery`, `messages-received`, `live-delivery-change` | 3 (polling), 4 (live) |
| Out-of-Band 2.0 | `https://didcomm.org/out-of-band/2.0` | `invitation` | 4 |

`return_route` matters because wallets have no public endpoint: replies travel back over the connection the wallet opened.

## 5. Transports

- **HTTPS** — `POST /didcomm` with `Content-Type: application/didcomm-encrypted+json`. `202 Accepted` when queued with no reply; `200` with the reply in the body when `return_route` asks for it; `413` above the size limit; `415` for other media types.
- **WebSocket** — `GET /ws` upgrades; one DIDComm message per frame; `return_route` is implied. Used for live delivery (Pickup `live-delivery-change`).

The node's DID document advertises one `DIDCommMessaging` service with both URIs and `accept: ["didcomm/v2"]`.

TLS is terminated in front of the node (reverse proxy) in production; the node itself speaks plain HTTP.

## 6. Node identity and keys

**Proposed:** the node's DID is `did:web:<domain>`, and the node serves its own document at `/.well-known/did.json` (configured with `ALMENA_DID_WEB_DOMAIN`). A domain-based DID is stable and lets other nodes find this one without a central registry.

**Proposed:** keys (one X25519 and one P-384 key-agreement key, one Ed25519 signing key) are generated on first start and stored in a Docker volume; a mounted secret can replace them.

## 7. Federation

**Proposed:** there is no node registry. When the next hop of a `forward` is a DID mediated by another node, this node resolves that DID, reads its `DIDCommMessaging` service (and `routingKeys`), wraps the message in a new `forward` if needed and POSTs it over HTTPS. Delivery retries with backoff.

## 8. Storage

**Decided — Redis**, as a service in `compose.yml`, with AOF persistence (`appendonly yes`, `appendfsync everysec`) so queues survive restarts.

Sketch of the key space (to be refined in phase 3):

| Key | Type | Holds |
|---|---|---|
| `mediation:{did}` | hash | Grant record for a mediated wallet DID |
| `recipient:{did}` | string | Owning mediation for a registered recipient DID |
| `queue:{did}` | stream | Queued envelopes, oldest first |
| `live:{did}` | pub/sub channel | Wakes the WebSocket session holding that DID |

## 9. Access and limits

**Decided — open with limits.** Any wallet may request mediation; limits protect the node and can be tightened later (invitation-only or allowlist) without changing the protocol.

**Proposed** settings (all `ALMENA_*` environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `ALMENA_MAX_MESSAGE_BYTES` | 1 MiB | Larger envelopes get `413` |
| `ALMENA_QUEUE_TTL` | 30 days | Undelivered messages are dropped after this |
| `ALMENA_QUEUE_MAX_MESSAGES` | 10 000 | Per recipient |
| `ALMENA_MAX_RECIPIENT_DIDS` | 100 | Per mediation |
| `ALMENA_RATE_LIMIT` | 60/min | Per client IP, on `POST /didcomm` |

## 10. Phases

1. **`almena-didcomm`** — workspace split; message model; JWK and key types; `did:key` and `did:peer` resolution; JWS sign/verify; anoncrypt and authcrypt; pack/unpack with consistency checks and `from_prior`; spec test vectors.
2. **Mediator skeleton** — node identity and keys, `did:web` document, `POST /didcomm`, Redis in Compose, Trust Ping, Discover Features, Report Problem, `return_route`.
3. **Mediation** — Coordinate Mediation 3.0, `forward`, Message Pickup 3.0 (polling), limits.
4. **Live and network** — WebSocket and live delivery, Out-of-Band invitations, forwarding to other nodes.

Each phase ends with `task check` green and the docs updated.
