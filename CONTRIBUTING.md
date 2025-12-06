# Contribuer a describe_me – Vue d'architecture

## Vue d'ensemble

```text
CLI ↔ AppContext ↔ Collectors ↔ History / Extensions ↔ Web (Axum + SSE) ↔ Security
```

- **CLI** (`src/bin/describe_me`, `src/bin/describe_me/cli.rs`, `src/bin/describe_me/args.rs`) : parse les flags, charge la config et orchestre les services; pas de logique metier lourde ici.
- **AppContext** (`src/application/context.rs`) : contient les services runtime (metadata store, HistoryService, cache conteneurs) et les rend injectables a la capture, a l'UI et aux tests.
- **Collectors** (`src/application/collectors/*`) : recuperent l'etat (sysinfo, services, sockets, updates, conteneurs). Ajouter un collector = implementer le trait `SnapshotCollector`/ajouter une fonction dans `core.rs`, brancher dans `collect_snapshot`.
- **History / Extensions** (`src/application/history.rs` + `history/service.rs`, `src/application/extensions.rs`) : mini time-series avec profils preconfigures; support des plugins externes via `describe_me_plugin_sdk` et `extensions` configurees.
- **Web (Axum + SSE)** (`src/application/web/mod.rs` et sous-modules) : routes HTML/SSE, cache de snapshots, handlers, security layers. Integre `AppState` (context + config statique) et expose les memes donnees que la CLI.
- **Security** (`src/application/web/security/*`) : politique, rate limiting, brute force guard, origin/CSP/headers. Les layers sont composes dans `web::serve_http_with_context`.

## Contribuer par brique

- **Ajouter/etendre un collector** : placer la logique dans `src/application/collectors/<topic>.rs`, exposer via `core.rs`, tester avec des snapshots factices; garder la couche CLI/web sans logique metier.
- **Modifier l'historique** : ajuster les profils dans `HistoryProfileConfig` (`src/application/history.rs`), utiliser `HistoryService::configure` pour les tests; ne pas mettre de policy dans la CLI.
- **Ajouter une extension/plugin** : suivre `docs/plugins.md` et `src/application/extensions.rs`; les plugins vivent dans `describe_me_plugin_sdk` et sont declares dans la config TOML.
- **Ajouter une route web/SSE** : router dans `src/application/web/mod.rs`, placer le handler dans `handlers.rs` ou un module dedie, exposer l'etat via `AppState`; si besoin d'une nouvelle source, ajoutez un collector/service applicatif.
- **Ajuster la securite web** : modifier les policies dans `src/application/web/security/policy.rs` ou les layers (origin, headers, rate limiting). Garder les couches separees (policy -> engine -> layers).

## Bonnes pratiques

- Respecter la separation **domaine** (types, erreurs) / **application** (services, orchestrateurs) / **infrastructure** (sysinfo, systemd, net, stockage). La CLI et l'UI ne doivent que piloter ces couches.
- Tests : placer les tests unitaires a proximite du code (`mod tests`), utiliser `AppContext::in_memory()` pour eviter l'IO disque; preferer des tests d'integration dans `tests/` pour les parcours complets CLI/web.
- Conserver les commentaires de module (`//!`) pour decrire roles/responsabilites; ajouter une note si vous creez un nouveau sous-module ou une nouvelle policy.
- Avant de pousser : `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --all-features` (ou au minimum les features concernees).
