# Installation

Ce document consolide les modes d'installation deja documentes dans le repo.

## Depuis le code source (cargo)

Exemple complet (CLI + web + config + net + systemd) :

```bash
cargo build --release --features "cli systemd config net web"
```

Commandes minimalistes (selon besoin) :

```bash
cargo build --features "cli"
cargo build --features "cli systemd config net"
```

Reference : `docs/utilisateurs/guide.md`.

## Paquet Debian (.deb)

```bash
make                    # lance un conteneur debian:12 et construit le .deb
ls target/debian/*.deb  # ex: target/debian/describe-me_0.1.0_amd64.deb
sudo dpkg -i target/debian/describe-me_0.1.0_amd64.deb
```

Ce flux est documente dans `README.md` et `scripts/deb-bookworm-build.sh`.
Le paquet installe la config sous `/etc/describe_me/config.toml`
(voir `packaging/config/config.toml`) et l'unite systemd durcie.

## Image Docker & compose

- Build local : `make docker-image` (tags `describe_me:<version>` + `latest`).
- Compose dev : `docker/docker-compose.yml` avec `docker/config.dev.toml`.
- Mode conteneur : `DESCRIBE_ME_CONTAINER=1` pour ignorer l'absence de systemd.

Reference : `README.md` (section "Image Docker & compose").

## FreeBSD

```sh
gmake freebsd-build          # features cli web config net
ls dist/freebsd/             # describe_me-freebsd-amd64, rc.describe_me, README
```

Installation manuelle best-effort et details : `packaging/freebsd/README.md`.
La config attendue est `/usr/local/etc/describe_me/config.toml`.

## Releases GitHub

Le workflow "Publish Release" attache un binaire `describe-me` et un paquet
`.deb` a chaque tag `v*`. Consulter la section "Releases" du repo.

Reference : `README.md` + `release.md`.

## crates.io / cargo install

A completer (non documente dans le repo).
