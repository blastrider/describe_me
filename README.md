# describe_me

Outil Rust minimaliste pour capturer l’état d’un serveur (CPU, RAM, disques, services systemd, sockets, mises à jour) et l’exposer via une CLI, une API SSE/HTML et une bibliothèque réutilisable. Fonctionne sans privilèges root et s’exécute aussi bien en binaire autonome qu’en tant que dépendance.

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

Pour HTTPS, ajoutez un bloc `[web.tls]` (voir `src/examples/config_tls.toml`) et pointiez votre navigateur sur `https://host:port`. La variante `config_http.toml` reste adaptée aux LAN en clair.

## Documentation

- Guide utilisateur complet : `docs/utilisateurs/guide.md`
- Architecture & internals : `docs/architecture.md`, `docs/application-layer.md`, `docs/web-security.md`, etc.
- Exemples de configuration : `src/examples/config.toml`, `src/examples/config_http.toml`, `src/examples/config_tls.toml`
- Packaging & service : `packaging/systemd/describe-me.service`

## Support & contributions

Questions / PRs bienvenues via GitHub. Merci de respecter la MSRV (1.90) et d’exécuter `cargo fmt && cargo clippy -- -D warnings` avant toute contribution.

## Licence

Apache-2.0 — voir `LICENSE`.
