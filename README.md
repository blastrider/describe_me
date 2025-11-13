# describe_me

Outil Rust minimaliste pour capturer l’état d’un serveur (CPU, RAM, disques, services systemd, sockets, mises à jour) et l’exposer via une CLI, une API SSE/HTML et une bibliothèque réutilisable. Fonctionne sans privilèges root et s’exécute aussi bien en binaire autonome qu’en tant que dépendance.

![describe_me logo](src/application/web/assets/gen.svg)

[![CI](https://github.com/blastrider/describe_me/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/blastrider/describe_me/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/blastrider/describe_me)](./LICENSE)
![MSRV](https://img.shields.io/badge/rustc-1.90%2B-informational?logo=rust)
![Security](https://img.shields.io/badge/security-cargo--audit%20%7C%20cargo--deny-informational)
![Platforms](https://img.shields.io/badge/platforms-Ubuntu%20%7C%20Debian%20%7C%20Fedora%20%7C%20Arch%20%7C%20Alpine%20%7C%20FreeBSD-blue)

## Points clés

- **Snapshot complet** : hostname, OS, uptime, charge, disques, services, sockets, trafic réseau, mises à jour.
- **CLI & Healthchecks** : sortie JSON lisible, `--check` (Nagios/Icinga), filtres config TOML.
- **Mode Web** : UI SSE auto-hébergée, rate limiting, jetons Argon2/bcrypt, HTTPS natif via `[web.tls]`.
- **Bibliothèque** : API stable (`SystemSnapshot`, `disk_usage`, `serve_http`) pour intégrer la collecte dans vos outils.

## Démarrage rapide

```bash
git clone https://github.com/Max-Perso/describe_me
cd describe_me
cargo build --release --features "cli systemd config net web"
cargo test --features "systemd config net web"

# Snapshot CLI
./target/release/describe-me --with-services --net-listen \
  --config ./src/examples/config.toml --pretty

# Dashboard SSE (HTTP)
./target/release/describe-me \
  --web 0.0.0.0:8080 \
  --web-token "$(./target/release/describe-me --hash-web-token 'secret')" \
  --with-services
```

Pour HTTPS, ajoutez un bloc `[web.tls]` (voir `src/examples/config_tls.toml`) ou placez l’app derrière un reverse-proxy (Caddy/Nginx/Traefik) en renseignant `allow_origins` et `trusted_proxies`. Le cookie `describe_me_session` est `HttpOnly+Secure`, donc il n’est envoyé qu’en HTTPS ; pour un dev local en clair, utilisez explicitement `--web-dev` (ou `web.dev_insecure_session_cookie = true`) et gardez ce mode hors prod.

## Paquet Debian

```bash
make                    # installe cargo-deb si nécessaire et construit le binaire
ls target/debian/*.deb  # ex: target/debian/describe-me_0.1.0_amd64.deb
sudo dpkg -i target/debian/describe-me_0.1.0_amd64.deb
```

Le paquet embarque l’unité systemd durcie fournie dans `packaging/systemd/describe-me.service` et gère automatiquement le rechargement/preset du service lors de l’installation.

## Documentation

- Guide utilisateur complet : `docs/utilisateurs/guide.md`
- Architecture & internals : `docs/architecture.md`, `docs/application-layer.md`, `docs/web-security.md`, etc.
- Exemples de configuration : `src/examples/config.toml`, `src/examples/config_http.toml`, `src/examples/config_tls.toml`
- Packaging & service : `packaging/systemd/describe-me.service`
- Environnement Vagrant multi‑distros (VMs + HTTPS + systemd) : `infras/README.md`

## Compatibilité

- Détection des mises à jour: validée sur Ubuntu, Debian et Fedora.
- Autres systèmes pris en charge (best‑effort): Arch/Manjaro (pacman), Alpine (apk), FreeBSD (pkg).

## Support & contributions

Questions / PRs bienvenues via GitHub. Merci de respecter la MSRV (1.90) et d’exécuter `cargo fmt && cargo clippy -- -D warnings` avant toute contribution.

## Licence

Apache-2.0 — voir `LICENSE`.
