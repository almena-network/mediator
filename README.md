# almena-mediator

The server side of Almena Network. It will implement [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/); for now the service is a skeleton — configuration, logging and an HTTP server with a health endpoint — next to `almena-didcomm`, the DIDComm library it will use (`crates/didcomm`). The DIDComm design and its phases are in [docs/didcomm.md](docs/didcomm.md).

## Run

```bash
cargo run
```

Or with Docker Compose (`task init` creates `.env` from `.env.example` to override the defaults):

```bash
docker compose up --build mediator
```

```bash
curl localhost:8080/health
```

## Configuration

| Variable                   | Default                  | Meaning                                                        |
| -------------------------- | ------------------------ | -------------------------------------------------------------- |
| `ALMENA_HOST`              | `0.0.0.0`                | Bind address                                                   |
| `ALMENA_PORT`              | `8080`                   | Bind port                                                      |
| `ALMENA_PUBLIC_URL`        | `http://localhost:8080`  | Public origin (no path); the mediator's DID is its `did:web`       |
| `ALMENA_KEYS_PATH`         | `data/keys.json`         | Mediator private keys, created on first start (`/data/keys.json` in the container) |
| `ALMENA_REDIS_URL`         | `redis://localhost:6379` | Redis (required); `memory://` for development without Redis    |
| `ALMENA_REDIS_PASSWORD`   | —                        | Redis password; Compose also sets it on its Redis. Unset: no authentication |
| `ALMENA_MAX_MESSAGE_BYTES` | `1048576`                | Largest DIDComm message accepted                               |
| `ALMENA_QUEUE_TTL`         | `2592000`                | Seconds before an undelivered message is dropped (30 days)     |
| `ALMENA_QUEUE_MAX_MESSAGES`| `10000`                  | Queued messages per mediation                                  |
| `ALMENA_QUEUE_MAX_BYTES`   | `104857600`              | Bytes of queued messages per mediation (100 MiB)               |
| `ALMENA_MAX_RECIPIENT_DIDS`| `100`                    | Registered recipient DIDs per mediation                        |
| `ALMENA_RECIPIENT_PROOF`   | `required`               | Registering another DID needs a proof signed by it (`off` to disable); see docs/didcomm.md §4 |
| `ALMENA_RATE_LIMIT`        | `60`                     | `POST /didcomm` per minute per client IP; `0` = off            |
| `ALMENA_CLIENT_IP_HEADER`  | —                        | Behind a proxy: header with the client IP (e.g. `x-forwarded-for`) |
| `ALMENA_FEDERATION`        | `true`                   | Relay forwards to other mediators; resolve their `did:web` over HTTPS |
| `ALMENA_OUTBOUND_ALLOW_INSECURE` | `false`            | Outbound HTTP and private addresses allowed — local multi-mediator testing only |
| `ALMENA_PUSH_MODE`         | `off`                    | `direct`: wake wallets through FCM/APNs with the wallet app's credentials |
| `ALMENA_PUSH_MIN_INTERVAL` | `60`                     | Least seconds between two pushes to one mediation               |
| `ALMENA_FCM_SERVICE_ACCOUNT` | —                      | Firebase service account key file (JSON)                        |
| `ALMENA_APNS_KEY_PATH`, `_KEY_ID`, `_TEAM_ID`, `_TOPIC` | — | APNs `.p8` key, its id, Apple team id, app bundle id (all four or none) |
| `ALMENA_APNS_SANDBOX`      | `false`                  | Use the APNs sandbox (development builds of the app)            |
| `ALMENA_LOG_FORMAT`        | `pretty`                 | `pretty` or `json`                                             |
| `RUST_LOG`                 | `info`                   | Log filter (`tracing` syntax)                                  |

The container image defaults `ALMENA_LOG_FORMAT` to `json`. Keep the keys file private: it is the mediator's identity.

## Endpoints

| Method | Path                    | Response                                                     |
| ------ | ----------------------- | ------------------------------------------------------------ |
| POST   | `/didcomm`              | DIDComm endpoint (`application/didcomm-encrypted+json`): Trust Ping, Discover Features, Coordinate Mediation 3.0, Routing 2.0 `forward`, Message Pickup 3.0, push notifications (FCM, APNs) |
| GET    | `/ws`                   | DIDComm over WebSocket; live delivery (Message Pickup 3.0 live mode) |
| GET    | `/.well-known/did.json` | The mediator's `did:web` DID document                            |
| GET    | `/oob/invitation`       | Out-of-Band 2.0 mediation invitation, and its `?_oob=` URL for QR codes |
| GET    | `/oob`                  | Human-readable page for the invitation URL                   |
| GET    | `/health`               | `{"status":"ok",…,"did":…,"storage":"ok","storage_kind":"redis"}`; `503` if storage is down |
| GET    | `/docs`                 | Interactive API reference (Scalar)                           |
| GET    | `/openapi.json`         | OpenAPI 3.1 document of the endpoints above                  |

The API reference is generated from the code: see http://localhost:8080/docs while the mediator runs.

## Development

Common commands are in the [Taskfile](Taskfile.yml) (needs [Task](https://taskfile.dev)):

```bash
task --list
```

`task init` creates `.env` from `.env.example`, `task dev` runs the mediator locally (with Redis in Docker) and `task dev:memory` without Docker, `task smoke` checks a running mediator end to end, `task check` runs lint and tests, `task up` / `task down` start and stop it in Docker.
