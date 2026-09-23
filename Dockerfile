# syntax=docker/dockerfile:1

# ---- build ----
FROM rust:1.98-slim-trixie AS build
WORKDIR /app

# Build dependencies first so they are cached across source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/didcomm/Cargo.toml crates/didcomm/
COPY crates/mediator/Cargo.toml crates/mediator/
RUN mkdir -p crates/didcomm/src crates/mediator/src \
    && touch crates/didcomm/src/lib.rs crates/mediator/src/lib.rs \
    && echo "fn main() {}" > crates/mediator/src/main.rs \
    && cargo build --release --locked -p almena-mediator \
    && rm -rf crates/didcomm/src crates/mediator/src

COPY crates ./crates
RUN touch crates/didcomm/src/lib.rs crates/mediator/src/lib.rs crates/mediator/src/main.rs \
    && cargo build --release --locked -p almena-mediator

# ---- runtime ----
FROM debian:trixie-slim AS runtime
# ca-certificates: the mediator talks HTTPS to other mediators (federation).
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home almena \
    && mkdir /data && chown almena /data
COPY --from=build /app/target/release/almena-mediator /usr/local/bin/almena-mediator
USER almena

ENV ALMENA_HOST=0.0.0.0 \
    ALMENA_PORT=8080 \
    ALMENA_KEYS_PATH=/data/keys.json \
    ALMENA_LOG_FORMAT=json \
    RUST_LOG=info
EXPOSE 8080
VOLUME /data

ENTRYPOINT ["almena-mediator"]
