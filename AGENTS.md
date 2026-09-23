# almena-mediator — notes for contributors and agents

Server of Almena Network, a decentralised messaging platform based on DIDComm Messaging v2.0
(https://identity.foundation/didcomm-messaging/spec/v2.0/). DIDs follow W3C DID (https://www.w3.org/TR/did/). Phases 1–4 of docs/didcomm.md are done: the DIDComm library, the mediator skeleton, mediation, and live delivery / invitations / federation.

This project is independent: it has its own Docker Compose file, env file and tooling.
It shares nothing with `../wallet` except the protocol; the wallet may later depend on the `almena-didcomm` crate (see docs/didcomm.md).

## Layout

Cargo workspace:

- `crates/didcomm/` — `almena-didcomm`: DIDComm v2.0 library (keys, JWS, JWE anoncrypt/authcrypt, messages, pack/unpack, `did:key`/`did:peer` resolution). No HTTP or storage.
  - `tests/spec/appendix.json` — the spec's Appendix A–C test vectors (errata noted in the file).
- `crates/mediator/` — `almena-mediator`: the service.
  - `config` reads `ALMENA_*` env vars; `identity` holds the mediator's `did:web`, keys (`ALMENA_KEYS_PATH`) and DID document.
  - `store/`: the `Store` trait with Redis and in-memory implementations, and a contract test both must pass.
  - `dispatch/`: unpacks what reaches `/didcomm` or `/ws` and dispatches — `protocols.rs` (Trust Ping, Discover Features, problem reports), `mediation.rs` (Coordinate Mediation, `forward`), `pickup.rs` (Message Pickup), `live.rs` (live-delivery sessions), `relay.rs` (forwarding to other mediators).
  - `transport.rs`: outbound HTTPS with the SSRF guard, and the `did:web` resolver. `oob.rs`: the Out-of-Band invitation.
  - `routes` is the axum router: HTTP and WebSocket endpoints, rate limit, HTTP status mapping.
  - `src/main.rs`: logging, start-up, graceful shutdown, `healthcheck` subcommand. `testing.rs` has a test mediator and wallets.
  - `examples/smoke.rs`: end-to-end client against a running mediator (`task smoke`).
- `Dockerfile`, `compose.yml` (mediator + Redis), `.env.example` — container build and local run. `data/` (local keys) is git-ignored.
- `docs/didcomm.md` — the DIDComm v2.0 design: role (pure mediator), protocols, crypto, storage (Redis), phases. Read it before DIDComm work and keep it current.

## Rules

- Everything is written in English.
- `almena-didcomm` denies `unwrap`/`expect` outside tests (`clippy.toml` allows them in tests) and uses `thiserror`; the mediator binary uses `anyhow`.
- Every HTTP endpoint is declared with `#[utoipa::path]` and registered through `OpenApiRouter` in `crates/mediator/src/routes.rs`, so it appears in `/openapi.json` and `/docs`. Keep the README endpoint table in sync.
- Tasks live in `Taskfile.yml` (`task --list`). Before finishing a change: `task check` (fmt check, clippy -D warnings, tests).
