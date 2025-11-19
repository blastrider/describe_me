## Unreleased

- Ajoutez vos changements ici.

## v0.2.0 - 2025-11-19

- Ajout d'un SDK `describe_me_plugin_sdk` (trait `Plugin`, macro `describe_me_plugin_main!`) pour écrire des collecteurs externes sérialisant un `PluginOutput` déterministe.
- Nouvelle commande `describe-me plugin run --name <plugin> [--arg ...] [--timeout <s>]` qui résout automatiquement `/usr/lib/describe_me/plugins/describe-me-plugin-<nom>`, épingle les binaires par SHA-256, gère les erreurs (exit code, timeout, JSON invalide) et affiche la sortie formatée.
- Intégration « extensions » : configuration `[extensions.plugins]`, exécution automatique lors des snapshots, données namespacées sous `extensions.<plugin>` (CLI, JSON, web) avec exposition contrôlée par `expose_extensions`.
- UI web : carte « Extensions » listant les collecteurs configurés, mise à jour SSE et sérialisation côté API.
- Fourniture d'un exemple de plugin dans `plugin-examples/certificates`.
- La cible `make` construit désormais automatiquement les plugins déclarés (ex: certificats) et les artefacts sont intégrés au paquet Debian/Vagrant (copie dans `/usr/bin` + configuration extensions).
- Ajout d'un module « history » persistant : enregistrement des snapshots dans une base redb, identifiant serveur stable, agrégation bucketisée et nouveaux profils/préréglages (`HistoryProfile`, `[history]` + overrides CLI).
- Nouvelle sous-commande `describe-me history …` et exposition HTTP (`/api/history`) pour interroger les métriques agrégées, également imprimables depuis la CLI.
- UI web : carte « Tendances » affichant les séries historiques (sparklines, moyennes), branchée sur l'API history/SSE et respectant le niveau d'exposition configuré.
- Build & packaging Debian : cible `make deb-bookworm`, helper containerisé, paramétrage des features deb/vagrant et exécution des builds en mode utilisateur pour livrer les nouvelles dépendances history.

## v0.1.3 - 2025-11-14

- Ajout d'un utilitaire `scripts/release-helper` + cibles `make release-{patch,minor,major}` pour incrémenter SemVer, mettre à jour `CHANGELOG.md`, commiter et tagger automatiquement.
- Nouveaux documents (README / release.md) décrivant le workflow d'intégration, l'utilisation de `cargo release` et la publication automatique des tags.
- Ajout d'un template de Pull Request rappelant les vérifications (CI, artefacts `.deb`, release-helper).
- Revue complète de la CI : job disponible sur `integration`, construction/archivage du paquet `.deb`, workflow `Publish Release` déclenché sur les tags `v*`.

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
