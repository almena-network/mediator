# syntax=docker/dockerfile:1

# ---- build ----
FROM rust:1.98-slim-trixie AS build
WORKDIR /app

# Build dependencies first so they are cached across source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# ---- runtime ----
FROM debian:trixie-slim AS runtime
RUN useradd --system --uid 10001 --no-create-home almena
COPY --from=build /app/target/release/almena-node /usr/local/bin/almena-node
USER almena

ENV ALMENA_HOST=0.0.0.0 \
    ALMENA_PORT=8080 \
    ALMENA_LOG_FORMAT=json \
    RUST_LOG=info
EXPOSE 8080

ENTRYPOINT ["almena-node"]
