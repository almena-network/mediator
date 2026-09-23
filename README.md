# almena-node

The server side of Almena Network. It will implement [DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/); for now it is only the service skeleton — configuration, logging and an HTTP server with a health endpoint. The DIDComm design is in [docs/didcomm.md](docs/didcomm.md).

## Run

```bash
cargo run
```

Or with Docker Compose (copy `.env.example` to `.env` to override the defaults):

```bash
docker compose up --build node
```

```bash
curl localhost:8080/health
```

## Configuration

| Variable            | Default   | Meaning                       |
| ------------------- | --------- | ----------------------------- |
| `ALMENA_HOST`       | `0.0.0.0` | Bind address                  |
| `ALMENA_PORT`       | `8080`    | Bind port                     |
| `ALMENA_LOG_FORMAT` | `pretty`  | `pretty` or `json`            |
| `RUST_LOG`          | `info`    | Log filter (`tracing` syntax) |

The container image defaults `ALMENA_LOG_FORMAT` to `json`.

## Endpoints

| Method | Path      | Response                                          |
| ------ | --------- | ------------------------------------------------- |
| GET    | `/health` | `{"status":"ok","service":"almena-node","version":…}` |

## Development

Common commands are in the [Taskfile](Taskfile.yml) (needs [Task](https://taskfile.dev)):

```bash
task --list
```

`task dev` runs the node locally, `task check` runs lint and tests, `task up` / `task down` start and stop it in Docker.
