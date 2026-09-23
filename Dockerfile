# syntax=docker/dockerfile:1

# ---- build ----
FROM rust:1.98-slim-trixie AS build
WORKDIR /app

# Build dependencies first so they are cached across source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/didcomm/Cargo.toml crates/didcomm/
COPY crates/node/Cargo.toml crates/node/
RUN mkdir -p crates/didcomm/src crates/node/src \
    && touch crates/didcomm/src/lib.rs crates/node/src/lib.rs \
    && echo "fn main() {}" > crates/node/src/main.rs \
    && cargo build --release --locked -p almena-node \
    && rm -rf crates/didcomm/src crates/node/src

COPY crates ./crates
RUN touch crates/didcomm/src/lib.rs crates/node/src/lib.rs crates/node/src/main.rs \
    && cargo build --release --locked -p almena-node

# ---- runtime ----
FROM debian:trixie-slim AS runtime
# ca-certificates: the node talks HTTPS to other nodes (federation).
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home almena \
    && mkdir /data && chown almena /data
COPY --from=build /app/target/release/almena-node /usr/local/bin/almena-node
USER almena

ENV ALMENA_HOST=0.0.0.0 \
    ALMENA_PORT=8080 \
    ALMENA_KEYS_PATH=/data/keys.json \
    ALMENA_LOG_FORMAT=json \
    RUST_LOG=info
EXPOSE 8080
VOLUME /data

ENTRYPOINT ["almena-node"]
