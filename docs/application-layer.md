# Couche Application

La couche `application` compose les services de `domain` et
`infrastructure` pour fournir les fonctionnalités haut niveau.

## Modules principaux

- `mod.rs`
  - `SystemSnapshot::capture[_with]` : point d’entrée principal. Mesure
    l’état système (CPU, mémoire, disques, services, mises à jour) et normalise
    l’agrégation (log `snapshot_captured`). La détection des mises à jour
    s’appuie sur `infrastructure::updates::gather_updates` (best effort).
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
    `exposure.listening_sockets`) et du statut des mises à jour (`exposure.updates`).
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
  - `mod.rs` expose également `POST /api/description` (authentifié) qui persiste
    la description libre via redb, afin que le bloc « Description » de l’interface
    web puisse être édité en direct.
- `metadata.rs`
  - Wrappe `infrastructure::storage::MetadataStore`, lui-même branché sur un
    `MetadataBackend` injectable (implémentation `redb` par défaut), et expose
    `set_server_description`, `load_server_description` et
    `clear_server_description`.
  - `capture_snapshot_with_view` enrichit `SnapshotView.server_description`
    avec la valeur persistée, en journalisant proprement les erreurs du backend
    sans casser la capture principale.
  - Le répertoire de stockage (`metadata.redb`) peut être écrasé via
    `override_state_directory` (utilisé automatiquement si `[runtime] state_dir`
    est défini dans la configuration TOML).
  - De nouveaux helpers gèrent les tags (`set_server_tags`, `add_server_tags`,
    `remove_server_tags`, `load_server_tags`) afin que la CLI et l’interface web
    puissent afficher et modifier les labels normalisés d’un serveur. L’UI web
    embarque désormais un formulaire (AJAX) pour ajouter/retirer/vider ces tags.
  - L’implémentation du backend peut être remplacée au démarrage (ex:
    MariaDB/Postgres/MongoDB) via `storage::set_metadata_backend_factory`
    pour réutiliser exactement la même API applicative.

- `net.rs` (feature `net`)
  - `net_listen()` : expose les sockets TCP/UDP en écoute via
    `infrastructure::net::linux`.

## Flux d’un snapshot

1. Construction d’`Exposure` depuis la CLI ou la config.
2. Capture du `SystemSnapshot`.
3. Transformation en `SnapshotView` (redaction/hints + description
   persistée).
4. Optionnellement, application des health checks et exposition via CLI,
   JSON (`--json` / `--pretty`) ou SSE.
