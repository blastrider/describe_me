## Unreleased

- Ajoutez vos changements ici.

## v0.1.2 - 2025-11-14

- Ajoutez vos changements ici.

## v0.1.1 - 2025-11-14

- Refus explicite d'exécuter `describe-me` en root (UID 0) côté CLI.
- Ajout d'une unité systemd durcie (`packaging/systemd/describe-me.service`) avec confinement maximal (DynamicUser, NoNewPrivileges, capabilities vidées, sandbox).
- Mode web : le jeton n'est plus accepté dans la query-string (`?token=`), uniquement via les en-têtes `Authorization: Bearer` ou `x-describe-me-token`, avec comparaison en temps constant et nouvelle UI de saisie.
- Mode web : le cookie d'accès est toujours marqué `Secure` et l'en-tête `Strict-Transport-Security` est envoyé par défaut (suppression de la feature `https_always`).
- Mode web : envoi par défaut de `Cross-Origin-Opener-Policy: same-origin` et `Cross-Origin-Embedder-Policy: require-corp` pour isoler la fenêtre et limiter les fuites XS-Leak.
- Mode web : possibilité de définir une allowlist d'origins (`allow_origins` / `--web-allow-origin`) pour accepter les proxys terminant TLS tout en restant strict côté CORS.
- Mode web : prise en charge d'un mode « trusted proxy » (`trusted_proxies` / `--web-trusted-proxy`) pour valider `X-Forwarded-For` et appliquer limites/affinités sur l'IP cliente effective.
- Mode web : plafonds globaux configurables (`route.global`, `sse.global`, `sse.max_stream_bytes`) et réponse SSE marquée `Cache-Control: no-store` pour limiter l'impact des flux longs.
- Collecte des mises à jour : exécution des commandes système via un wrapper sécurisé (env nettoyé, umask 077, timeout, logs de durée/status) avec arrêt forcé en cas de dépassement.
- Chaîne supply-chain renforcée : job GitHub Actions dédié (`supply-chain`), intégration `cargo crev`, génération et publication du SBOM CycloneDX, recommandations de signature GPG/cosign.
- Résilience parsing : proptests ciblant `/proc/net`, `apt/dnf/apk`, `/proc/self/mountinfo`, et nouveaux fuzzers `cargo-fuzz` sur les parseurs sensibles.

