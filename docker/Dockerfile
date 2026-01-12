# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.90.0
ARG TARGET_TRIPLE=x86_64-unknown-linux-musl

############################
# Étape 1 : build du binaire + plugin
############################
FROM rust:${RUST_VERSION}-alpine3.20 AS build
ARG TARGET_TRIPLE
ARG APP_FEATURES="cli web config systemd net journald"
ARG APP_BIN=describe-me
ARG PLUGIN_BIN=describe-me-plugin-certificates
ARG CONTAINERS_PLUGIN_BIN=describe-me-plugin-containers
ARG PLUGIN_MANIFEST=plugin-examples/certificates/Cargo.toml

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_TARGET_DIR=/app/target

# Outils de build pour musl et strip
RUN apk add --no-cache build-base musl-dev pkgconfig ca-certificates

WORKDIR /app

COPY . .

RUN rustup target add ${TARGET_TRIPLE}

# Build statique musl des binaires
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --target ${TARGET_TRIPLE} --features "${APP_FEATURES}"

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --manifest-path ${PLUGIN_MANIFEST} --target ${TARGET_TRIPLE}

# Préparation du système de fichiers final (proprio non-root pour l'état)
RUN --mount=type=cache,target=/app/target \
    set -eux; \
    strip target/${TARGET_TRIPLE}/release/${APP_BIN}; \
    strip target/${TARGET_TRIPLE}/release/${PLUGIN_BIN}; \
    strip target/${TARGET_TRIPLE}/release/${CONTAINERS_PLUGIN_BIN}; \
    install -Dm755 target/${TARGET_TRIPLE}/release/${APP_BIN} /dist/usr/bin/${APP_BIN}; \
    install -Dm755 target/${TARGET_TRIPLE}/release/${PLUGIN_BIN} /dist/usr/lib/describe_me/plugins/${PLUGIN_BIN}; \
    install -Dm755 target/${TARGET_TRIPLE}/release/${CONTAINERS_PLUGIN_BIN} /dist/usr/lib/describe_me/plugins/${CONTAINERS_PLUGIN_BIN}; \
    install -Dm600 packaging/config/config.toml /dist/etc/describe_me/config.toml; \
    mkdir -p /dist/var/lib/describe-me /dist/var/tmp; \
    chown -R 1000:1000 /dist/var/lib/describe-me /dist/etc/describe_me /dist/usr/lib/describe_me

############################
# Étape 1b : récupérer journalctl (optionnel)
############################
FROM debian:12-slim AS journalctl
RUN apt-get update && \
    apt-get install -y --no-install-recommends systemd ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    mkdir -p /dist/usr/bin; \
    cp /usr/bin/journalctl /dist/usr/bin/journalctl; \
    ldd /usr/bin/journalctl | awk '{print $3}' | grep '^/' | xargs -r -I{} cp --parents {} /dist

############################
# Étape 2 : image finale (debian-slim pour disposer de journalctl/libsystemd)
############################
FROM debian:13-slim

LABEL org.opencontainers.image.title="describe-me"
LABEL org.opencontainers.image.description="Server snapshot & health CLI + web dashboard"
LABEL org.opencontainers.image.source="https://github.com/Max-Perso/describe_me"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Certificats + binaires statiques
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /dist/ /

# journalctl + libs (installés dans l'image finale)
RUN apt-get update && \
    apt-get install -y --no-install-recommends systemd ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV RUST_LOG=info \
    DESCRIBE_ME_STATE_DIR=/var/lib/describe-me

VOLUME ["/var/lib/describe-me", "/etc/describe_me"]

EXPOSE 8080

USER 1000:1000

ENTRYPOINT ["/usr/bin/describe-me"]
CMD ["--help"]
