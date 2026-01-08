# Migration_Domain_Driven

## But & Non-buts
- But: reorganiser le code par contextes (DDD + ports/adapters) sans changer le comportement.
- But: conserver une facade publique stable via `src/api.rs` et re-exports explicites.
- But: migration incrementale, chaque phase compile et passe les tests cibles.
- Non-but: modifier les APIs publiques, signatures, formats ou semantics.
- Non-but: changer la securite, les politiques ou les comportements par defaut.
- Non-but: toucher CI, secrets, ou packaging.

## Principes de migration
- Chaque phase doit compiler; pas de mouvements massifs sans shims.
- Garder `crate::api` comme unique facade stable; `crate::domain` reste facade de compatibilite.
- Introduire des shims temporaires (`pub use`) dans les anciens modules.
- Isoler les ports (traits) dans `contexts/*/ports` et les adapters dans `contexts/*/adapters` ou `platform`.
- Conserver les `cfg(feature = "...")` aux memes frontieres pour limiter la compilation.
- Preferer des moves fichier-par-fichier avec tests courts a chaque phase.

## Arborescence cible complete
[Inférence] Proposition d'arborescence cible basee sur les modules existants et les contextes demandes.

```text
src/
  api.rs
  api/
    system.rs
    metadata.rs
    history.rs
    exposure.rs
    errors.rs
    health.rs
    logs.rs
    net.rs
    web.rs
    containers.rs
    plugins.rs
    pagination.rs
    logging.rs
    config/
      mod.rs
      runtime.rs
  contexts/
    snapshot/
      mod.rs
      domain/
        mod.rs
        model.rs
      app/
        mod.rs
        collectors/
          mod.rs
          core.rs
          net.rs
          services.rs
          updates.rs
          containers.rs
        exposure.rs
        health.rs
        metrics.rs
        net.rs
        services.rs
        updates.rs
      ports/
        mod.rs
        system.rs
        net.rs
        services.rs
        updates.rs
      adapters/
        mod.rs
        system.rs
        net.rs
        services.rs
        updates.rs
    metadata/
      mod.rs
      domain/
        mod.rs
        server_metadata.rs
      app/
        mod.rs
        registry.rs
      ports/
        mod.rs
        store.rs
      adapters/
        mod.rs
        storage.rs
    history/
      mod.rs
      domain/
        mod.rs
        history_dto.rs
        history_profile.rs
      app/
        mod.rs
        service.rs
        backend.rs
        config.rs
      ports/
        mod.rs
        history_store.rs
      adapters/
        mod.rs
        history_store.rs
    logs/
      mod.rs
      domain/
        mod.rs
        model.rs
      app/
        mod.rs
      ports/
        mod.rs
        logs_reader.rs
      adapters/
        mod.rs
        logs_reader.rs
    extensions/
      mod.rs
      domain/
        mod.rs
        plugin.rs
      app/
        mod.rs
        policy.rs
        runner.rs
      ports/
        mod.rs
        plugin_runner.rs
      adapters/
        mod.rs
        process_runner.rs
    web/
      mod.rs
      domain/
        mod.rs
      app/
        mod.rs
        handlers.rs
        services.rs
        state.rs
        sse.rs
        auth.rs
        tls.rs
        csp.rs
        error.rs
        origin.rs
        updates_cache.rs
        views.rs
        assets/
          mod.rs
          bundle.rs
          gen.svg
          js/
            ui.js
            bootstrap.js
            token.js
            sse.js
            preamble.js
            logs.js
            history-trends.js
            containers.js
            disk-utils.js
            drag.js
            background-grid.js
            tags-editor/
              tile.js
              helpers.js
              manager.js
        templates/
          index.html
          containers.html
          logs.html
          updates.html
          containers.css
          logs.css
          updates.css
          styles/
            variables.css
            base.css
            grid.css
            animations.css
            components.css
            overlays.css
            light-theme.css
          partials/
            main_layout.html
            header.html
            footer.html
            primary_grid.html
            token_overlay.html
            sockets.html
            services.html
            raw.html
        security/
          mod.rs
          auth.rs
          session.rs
          sse.rs
          tests_auth.rs
          tests_bruteforce.rs
          tests_common.rs
          tests_token_affinity.rs
          limits/
            mod.rs
            state.rs
            policy.rs
            engine.rs
            global_slots.rs
            rate_limiter.rs
            brute_force_guard.rs
            sliding.rs
            token_affinity.rs
            sse_admission.rs
            tests_policy.rs
  domain/
    mod.rs
    error.rs
    model.rs
    history_dto.rs
    history_profile.rs
    plugin.rs
    server_metadata.rs
    config.rs
  platform/
    mod.rs
    README-internals.md
    sysinfo.rs
    system/
      mod.rs
    net/
      mod.rs
      linux.rs
      freebsd.rs
    logs/
      mod.rs
      linux.rs
      freebsd.rs
    services/
      mod.rs
      systemd.rs
      freebsd.rs
    updates.rs
  kernel/
    mod.rs
    context.rs
    security.rs
    logging.rs
    error.rs
  shared/
    mod.rs
    shared_slice.rs
    pagination.rs
    sync.rs
    cache.rs
  internals/
    mod.rs
    metadata.rs
    net.rs
    systemd.rs
    updates.rs
    sysinfo.rs
  bin/
    describe_me/
      mod.rs
      cli.rs
      args.rs
      allowlists.rs
      exposure.rs
      cmd_logs.rs
      cmd_plugin.rs
      cmd_metadata.rs
      cmd_history.rs
      run/
        mod.rs
        capture.rs
        config.rs
        health.rs
        render.rs
        web.rs
    describe-me.rs
    describe-me-plugin-containers.rs
```

## Strategie de compatibilite API
- Modules publics stables: `crate::api`, `crate::domain`, `crate::security`, `crate::internals` (cfg), re-exports plats existants via `pub use crate::api::*`.
- Shims temporaires:
  - `src/application/*` et `src/infrastructure/*` deviennent des re-exports internes vers `contexts/*` et `platform/*`.
  - `src/domain/*` re-exporte les types des contextes (`contexts/*/domain`) pour garder `crate::domain::*` stable.
  - `src/security.rs` re-exporte `kernel::security` pour garder `crate::security::*` stable.
- Politique de deprecation:
  - Garder les re-exports plats actuels dans `src/api.rs` marques `#[doc(hidden)]`.
  - Optionnel: ajouter `#[deprecated(note = "use describe_me::api::...")]` aux re-exports plats lors d'une release mineure, sans suppression.

## Phasage detaille

### Phase 1 - Squelette DDD et points d'entree
- Objectifs:
  - Creer `contexts/`, `kernel/`, `platform/`, `shared/`, `internals/` sans bouger le code.
  - Declarer les modules racines dans `src/lib.rs`.
- Fichiers/dossiers impactes:
  - `src/lib.rs`
  - `src/contexts/mod.rs`
  - `src/kernel/mod.rs`
  - `src/platform/mod.rs`
  - `src/shared/mod.rs`
  - `src/internals/mod.rs`
- Actions (checklist):
  - [ ] Ajouter les dossiers et `mod.rs` avec re-exports vides ou stubs.
  - [ ] Garder `application/` et `infrastructure/` intacts.
  - [ ] Ajouter des `pub(crate) use` pour preparer les shims.
- Definition of Done:
  - `cargo check --workspace --no-default-features` passe.
- Risques + rollback simple:
  - Risque: conflits de noms de modules.
  - Rollback: retirer les nouveaux `mod.rs` et leurs declarations.

### Phase 2 - Facade API stable et sous-modules
- Objectifs:
  - Splitter `src/api.rs` en sous-modules `src/api/*` sans changer les re-exports publics.
  - Preparer `crate::api::*` a pointer vers `contexts/*`.
- Fichiers/dossiers impactes:
  - `src/api.rs`
  - `src/api/*.rs`
- Actions (checklist):
  - [ ] Creer `src/api/*.rs` et y deplacer le contenu par sous-module (system, metadata, history, web, etc.).
  - [ ] Garder `src/api.rs` comme routeur de re-exports.
  - [ ] Conserver les `cfg(feature = "...")` existants au meme niveau.
- Definition of Done:
  - `cargo test --workspace --no-default-features` passe.
- Risques + rollback simple:
  - Risque: erreurs de resolution de module.
  - Rollback: revenir a un unique `src/api.rs`.

### Phase 3 - Kernel + shared (utilitaires transverses)
- Objectifs:
  - Regrouper les utilitaires transverses et la securite dans `kernel/` et `shared/`.
- Fichiers/dossiers impactes:
  - `src/shared.rs`
  - `src/application/sync.rs`
  - `src/application/pagination.rs`
  - `src/application/logging.rs`
  - `src/application/error.rs`
  - `src/security.rs`
  - `src/application/shared/*`
- Actions (checklist):
  - [ ] Deplacer `SharedSlice` vers `shared/shared_slice.rs` et re-exporter via `shared/mod.rs`.
  - [ ] Deplacer `sync` et `pagination` vers `shared/`.
  - [ ] Deplacer `logging` et `error` vers `kernel/`.
  - [ ] Deplacer `security` vers `kernel/` et re-exporter via `src/security.rs`.
  - [ ] Ajouter des shims dans les anciens chemins.
- Definition of Done:
  - `cargo test --workspace --features "cli"` passe.
- Risques + rollback simple:
  - Risque: cycles de dependances (kernel <-> contexts).
  - Rollback: restaurer les fichiers a leur emplacement initial et garder les shims dans `kernel/`.

### Phase 4 - Context snapshot (system/capture)
- Objectifs:
  - Regrouper la capture systeme (snapshot, collectors, net, services, updates, containers).
  - Introduire ports/adapters pour backends OS.
- Fichiers/dossiers impactes:
  - `src/application/collectors/*`
  - `src/application/containers.rs`
  - `src/application/exposure.rs`
  - `src/application/health.rs`
  - `src/application/metrics.rs`
  - `src/application/net.rs`
  - `src/application/services.rs`
  - `src/domain/model.rs`
  - `src/infrastructure/system/*`
  - `src/infrastructure/sysinfo.rs`
  - `src/infrastructure/net/*`
  - `src/infrastructure/services/*`
  - `src/infrastructure/updates.rs`
- Actions (checklist):
  - [ ] Deplacer les types `SystemSnapshot`, `DiskUsage`, `ServiceInfo`, etc. vers `contexts/snapshot/domain`.
  - [ ] Scinder `domain/model.rs` par contexte (snapshot/logs/etc.) et re-exporter via `src/domain/mod.rs`.
  - [ ] Deplacer les collectors et services applicatifs vers `contexts/snapshot/app`.
  - [ ] Creer `ports` (traits) pour system/net/services/updates.
  - [ ] Deplacer les backends OS vers `platform/` et les brancher comme adapters.
  - [ ] Laisser des shims dans `application/*` et `infrastructure/*`.
- Definition of Done:
  - `cargo test --workspace --features "cli net systemd"` passe.
- Risques + rollback simple:
  - Risque: mauvaise propagation des `cfg(feature)`.
  - Rollback: remettre les backends sous `infrastructure/` et garder les traits dans `application/`.

### Phase 5 - Context metadata
- Objectifs:
  - Isoler la gestion des metadonnees serveur.
- Fichiers/dossiers impactes:
  - `src/application/metadata.rs`
  - `src/application/metadata/registry.rs`
  - `src/domain/server_metadata.rs`
  - `src/infrastructure/storage.rs`
- Actions (checklist):
  - [ ] Deplacer le modele metadata vers `contexts/metadata/domain`.
  - [ ] Deplacer les services metadata vers `contexts/metadata/app`.
  - [ ] Creer un port `Store` et un adapter storage.
  - [ ] Mettre a jour `AppContext` pour pointer vers le nouveau chemin.
- Definition of Done:
  - `cargo test --workspace --features "cli"` passe.
- Risques + rollback simple:
  - Risque: casse des tests metadata.
  - Rollback: remettre `storage.rs` et `metadata.rs` a leur emplacement initial.

### Phase 6 - Context history
- Objectifs:
  - Isoler l'historique et ses backends.
- Fichiers/dossiers impactes:
  - `src/application/history.rs`
  - `src/application/history/*`
  - `src/application/history_config.rs`
  - `src/domain/history_dto.rs`
  - `src/domain/history_profile.rs`
  - `src/infrastructure/history.rs`
- Actions (checklist):
  - [ ] Deplacer les DTOs et profiles vers `contexts/history/domain`.
  - [ ] Deplacer service/backend vers `contexts/history/app`.
  - [ ] Creer ports + adapters pour la persistence.
  - [ ] Re-exporter via `src/domain/mod.rs` et `src/api/history.rs`.
- Definition of Done:
  - `cargo test --workspace --features "cli"` passe.
- Risques + rollback simple:
  - Risque: rupture de `HistoryService` dans `AppContext`.
  - Rollback: restaurer `application/history` et garder les adapters en interne.

### Phase 7 - Context logs
- Objectifs:
  - Isoler la lecture des logs systeme.
- Fichiers/dossiers impactes:
  - `src/application/logs.rs`
  - `src/domain/model.rs` (HostLogEntry/HostLogsPage)
  - `src/infrastructure/logs/*`
- Actions (checklist):
  - [ ] Deplacer les types de logs vers `contexts/logs/domain`.
  - [ ] Deplacer le service vers `contexts/logs/app`.
  - [ ] Creer ports/adapters pour les backends Linux/FreeBSD.
- Definition of Done:
  - `cargo test --workspace --features "cli"` passe.
- Risques + rollback simple:
  - Risque: regressions sur journald.
  - Rollback: garder `infrastructure/logs` en place et re-router via shim.

### Phase 8 - Context extensions/plugins
- Objectifs:
  - Isoler l'execution des plugins/extensions.
- Fichiers/dossiers impactes:
  - `src/application/extensions.rs`
  - `src/application/extensions/policy.rs`
  - `src/domain/plugin.rs`
- Actions (checklist):
  - [ ] Deplacer le modele plugin vers `contexts/extensions/domain`.
  - [ ] Deplacer l'execution + policy vers `contexts/extensions/app`.
  - [ ] Creer un port `PluginRunner` et un adapter process.
- Definition of Done:
  - `cargo test --workspace --features "serde config"` passe.
- Risques + rollback simple:
  - Risque: regression de securite sur les plugins.
  - Rollback: garder `application/extensions.rs` en place et re-exporter.

### Phase 9 - Context web
- Objectifs:
  - Regrouper le serveur web (handlers, assets, security, SSE).
- Fichiers/dossiers impactes:
  - `src/application/web/*`
  - `src/application/error.rs` (si non deja migre)
  - `src/bin/describe_me/run/*`
- Actions (checklist):
  - [ ] Deplacer le web vers `contexts/web/app` sans changer les routes.
  - [ ] Garder les templates/assets en place et ajuster les chemins.
  - [ ] Isoler les modules security sous `contexts/web/app/security`.
  - [ ] Re-exporter via `src/api/web.rs` et `src/api/errors.rs`.
- Definition of Done:
  - `cargo test --workspace --features "cli web config"` passe.
- Risques + rollback simple:
  - Risque: casse des chemins d'assets.
  - Rollback: garder `application/web` et re-pointer les bins.

### Phase 10 - Nettoyage et consolidation
- Objectifs:
  - Retirer progressivement `application/` et `infrastructure/` (ou les figer en shims).
  - Stabiliser les dependances et documenter la nouvelle arborescence.
- Fichiers/dossiers impactes:
  - `src/application/*`
  - `src/infrastructure/*`
  - `src/lib.rs`
  - `docs/*` (si doc d'architecture)
- Actions (checklist):
  - [ ] Remplacer le contenu restant par des re-exports ou supprimer apres verification.
  - [ ] Ajouter une note de migration interne (docs/ ou README technique).
  - [ ] Verifier que `crate::api` et `crate::domain` restent inchanges.
- Definition of Done:
  - `cargo test --workspace --all-features` passe.
- Risques + rollback simple:
  - Risque: oubli d'un import interne.
  - Rollback: restaurer les anciens modules via shims.

## Mapping de migration (ancien -> nouveau)
[Inférence] Mapping propose; ajuster si un module a des dependances transverses non visibles.

- `src/application/context.rs` -> `src/kernel/context.rs`
- `src/application/collectors/*` -> `src/contexts/snapshot/app/collectors/*`
- `src/application/containers.rs` -> `src/contexts/snapshot/app/containers.rs`
- `src/application/exposure.rs` -> `src/contexts/snapshot/app/exposure.rs`
- `src/application/health.rs` -> `src/contexts/snapshot/app/health.rs`
- `src/application/metrics.rs` -> `src/contexts/snapshot/app/metrics.rs`
- `src/application/net.rs` -> `src/contexts/snapshot/app/net.rs`
- `src/application/services.rs` -> `src/contexts/snapshot/app/services.rs`
- `src/domain/model.rs` -> `src/contexts/snapshot/domain/model.rs`
- `src/infrastructure/system/*` -> `src/platform/system/*`
- `src/infrastructure/sysinfo.rs` -> `src/platform/sysinfo.rs`
- `src/infrastructure/net/*` -> `src/platform/net/*`
- `src/infrastructure/services/*` -> `src/platform/services/*`
- `src/infrastructure/updates.rs` -> `src/platform/updates.rs`
- `src/application/metadata.rs` -> `src/contexts/metadata/app/mod.rs`
- `src/application/metadata/registry.rs` -> `src/contexts/metadata/app/registry.rs`
- `src/domain/server_metadata.rs` -> `src/contexts/metadata/domain/server_metadata.rs`
- `src/infrastructure/storage.rs` -> `src/contexts/metadata/adapters/storage.rs`
- `src/application/history.rs` -> `src/contexts/history/app/mod.rs`
- `src/application/history/*` -> `src/contexts/history/app/*`
- `src/application/history_config.rs` -> `src/contexts/history/app/config.rs`
- `src/domain/history_dto.rs` -> `src/contexts/history/domain/history_dto.rs`
- `src/domain/history_profile.rs` -> `src/contexts/history/domain/history_profile.rs`
- `src/infrastructure/history.rs` -> `src/contexts/history/adapters/history_store.rs`
- `src/application/logs.rs` -> `src/contexts/logs/app/mod.rs`
- `src/domain/model.rs` (HostLogEntry, HostLogsPage) -> `src/contexts/logs/domain/model.rs`
- `src/infrastructure/logs/*` -> `src/platform/logs/*`
- `src/application/extensions.rs` -> `src/contexts/extensions/app/runner.rs`
- `src/application/extensions/policy.rs` -> `src/contexts/extensions/app/policy.rs`
- `src/domain/plugin.rs` -> `src/contexts/extensions/domain/plugin.rs`
- `src/application/web/*` -> `src/contexts/web/app/*`
- `src/application/web/security/*` -> `src/contexts/web/app/security/*`
- `src/application/error.rs` -> `src/kernel/error.rs`
- `src/application/logging.rs` -> `src/kernel/logging.rs`
- `src/application/pagination.rs` -> `src/shared/pagination.rs`
- `src/application/sync.rs` -> `src/shared/sync.rs`
- `src/application/shared/cache.rs` -> `src/shared/cache.rs`
- `src/shared.rs` -> `src/shared/shared_slice.rs` + `src/shared/mod.rs`
- `src/security.rs` -> `src/kernel/security.rs` (re-export via `src/security.rs`)
- `src/infrastructure/README-internals.md` -> `src/platform/README-internals.md`

## Regles de dependances (ports/adapters)
- `contexts/*/domain` depend seulement de `shared` et `kernel` (pas de `platform`, pas d'autres contexts).
- `contexts/*/ports` depend de `contexts/*/domain` et `shared`.
- `contexts/*/app` depend de `contexts/*/domain`, `contexts/*/ports`, `kernel`, `shared`.
- `contexts/*/adapters` depend de `contexts/*/ports`, `contexts/*/domain`, `platform`, `shared`.
- `platform` depend seulement de `shared` et crates externes; jamais de `contexts/*`.
- `api` depend de `contexts/*` et `domain` (facades uniquement).
- `domain` (facade) depend des `contexts/*/domain`.
- `kernel` depend de `shared` et peut exposer des abstractions communes.
- `internals` depend des modules exposes par `contexts/*` et `platform` sous `cfg(test)` / `cfg(feature = "internals")`.

## Plan de tests/validation
- Phase 1-2:
  - `cargo test --workspace --no-default-features`
- Phase 3:
  - `cargo test --workspace --features "cli"`
- Phase 4:
  - `cargo test --workspace --features "cli net systemd"`
- Phase 5-6:
  - `cargo test --workspace --features "cli config"`
- Phase 7:
  - `cargo test --workspace --features "cli"`
- Phase 8:
  - `cargo test --workspace --features "serde config"`
- Phase 9:
  - `cargo test --workspace --features "cli web config"`
- Phase 10 (fin de migration):
  - `cargo fmt --all`
  - `cargo clippy --all-targets --all-features -D warnings`
  - `cargo test --all-features`
  - `cargo deny check` (deny.toml present)
  - `cargo audit` (si utilise par l'equipe)

## Checklist finale (pre-release)
- [ ] `cargo fmt --all`
- [ ] `cargo clippy --all-targets --all-features -D warnings`
- [ ] `cargo test --all-features`
- [ ] `cargo deny check`
- [ ] `cargo audit`
- [ ] Verifier `crate::api` et `crate::domain` sans regressions de re-exports
- [ ] Verifier la matrice de features (no-default-features, cli, net, systemd, web, internals)
