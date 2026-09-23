# almena-node — notes for contributors and agents

Server of Almena Network, a decentralised messaging platform based on DIDComm Messaging v2.1
(https://identity.foundation/didcomm-messaging/spec/v2.1/). DIDs follow W3C DID (https://www.w3.org/TR/did/). No DIDComm features yet.

This project is independent: it has its own Docker Compose file, env file and tooling.
It shares nothing with `../wallet` except the protocol; the wallet may later depend on the `almena-didcomm` crate (see docs/didcomm.md).

## Layout

- `src/lib.rs` — library: `config` (reads `ALMENA_*` env vars) and `routes` (axum router).
- `src/main.rs` — binary: logging, server start, graceful shutdown, `healthcheck` subcommand.
- `Dockerfile`, `compose.yml`, `.env.example` — container build and local run.
- `docs/didcomm.md` — the DIDComm v2.1 design: role (pure mediator), protocols, crypto, storage (Redis), phases. Read it before DIDComm work and keep it current.

## Rules

- Everything is written in English.
- Tasks live in `Taskfile.yml` (`task --list`). Before finishing a change: `task check` (fmt check, clippy -D warnings, tests).
