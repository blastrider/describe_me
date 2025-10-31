# Couche Application

La couche `application` compose les services de `domain` et
`infrastructure` pour fournir les fonctionnalités haut niveau.

## Modules principaux

- `mod.rs`
  - `SystemSnapshot::capture[_with]` : point d’entrée principal. Mesure
    l’état système (CPU, mémoire, disques, services) et normalise
    l’agrégation (log `snapshot_captured`).
  - `disk_usage()` : expose l’agrégat disque directement depuis
    l’infrastructure.
  - `load_config_from_path` (feature `config`) : lit un TOML,
    journalise les erreurs via `LogEvent::ConfigError`.
  - `filter_services` : applique la allowlist déclarée dans la config.

- `health.rs`
  - Parse et évalue des checks (`mem`, `disk`, `service`).
  - `eval_checks` retourne la sévérité maximale et les messages détaillés.

- `exposure.rs`
  - Détermine quels champs sensibles sont exposés ou tronqués.
  - `SnapshotView::new` inclut maintenant des helpers (`build_sensitive_field`,
    `DiskUsageView::from_snapshot`) pour uniformiser la redaction.
  - Fournit `Exposure` et `SnapshotView` utilisés par le CLI et le serveur web.
  - Gère également l’exposition des sockets en écoute (via
    `exposure.listening_sockets`).
  - Les listes volumineuses (services, sockets, partitions) sont partagées via
    `SharedSlice` (`src/shared.rs`), qui s’appuie sur `Arc<Vec<T>>` pour
    limiter les clones lorsqu’on sérialise la même vue plusieurs fois.

- `logging.rs`
  - `init_logging` : configure `tracing_subscriber`, journald (optionnel),
    fallback stderr.
  - `LogEvent` centralise tous les événements structurés du CLI et du serveur web.

- `web/`
  - `mod.rs` : service Axum + SSE (`serve_http`), gestion du shutdown,
    headers de sécurité (CSP, CORP…).
  - `security/` : autorisation, rate limiting, backoff (voir
    `docs/web-security.md` pour les détails).
  - `sse.rs` : envoi périodique du snapshot, application des règles
    d’exposition.
  - `template.rs` : HTML/CSS/JS embarqués pour l’UI.
  - `security.rs` (nouvelle structure) s’appuie sur
    `RateLimiter`, `FailureTracker`, `TokenSpreadTracker` pour limiter la
    duplication.

- `net.rs` (feature `net`)
  - `net_listen()` : expose les sockets TCP/UDP en écoute via
    `infrastructure::net::linux`.

## Flux d’un snapshot

1. Construction d’`Exposure` depuis la CLI ou la config.
2. Capture du `SystemSnapshot`.
3. Transformation en `SnapshotView` (redaction/hints).
4. Optionnellement, application des health checks et exposition via CLI,
   JSON (`--json` / `--pretty`) ou SSE.
