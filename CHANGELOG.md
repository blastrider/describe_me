## Unreleased

- Web (auth/session) : sessions réutilisables avec TTL glissant aligné sur `WEB_SESSION_SECONDS`, cookie `describe_me_session` rafraîchi automatiquement via `attach_session_cookie` sur toutes les routes protégées, et fallback Bearer conservé pour la CLI.
- Web UI : login modal en JSON vers `/auth/login` (same-origin), SSE basculé sur `EventSource('/sse')` avec re-auth propre sur 401, fetch APIs (`history`, `logs`, `containers`, tags) utilisant uniquement le cookie HttpOnly.
- Sécurité : cookie Max-Age synchronisé avec le TTL serveur, suppression du stockage client de jeton, 401 nettoie le cookie côté backend.
- Docs : ajout de `docs/web-auth.md` décrivant le flux d'auth web (serveur + frontend) et les points de vigilance.
- API : le réexport global `pub use crate::api::*;` reste provisoire et sera supprimé lors d'une prochaine version majeure ; utilisez les modules explicites (`describe_me::api::history::*`, etc.).

## v0.5.0 - 2025-12-01

- Ajoutez vos changements ici.

## v0.4.0 - 2025-11-26

- Ajoutez vos changements ici.

## v0.3.0 - 2025-11-26

- Aucun changement documenté pour cette version.

## v0.2.6 - 2025-11-24

- Logs journald : nouvelle API/CLI (`describe-me logs`) et UI (tuile + page `/logs`) pour lire les logs de l'hôte ; support journald côté conteneur avec socket monté et image Debian 13.
- Docker : image finale basée sur `debian:13-slim` (inclut journalctl/libsystemd) ; compose dev ajusté pour monter le socket journald, utiliser PID host en non-root, ignorer systemctl en conteneur et assouplir les limites `/api/logs`.
- SSE : désactivation de la collecte systemd quand `DESCRIBE_ME_CONTAINER=1` pour éviter les erreurs `systemctl` en conteneur.
- Docs : ajout d'une section complète sur la lecture des logs en Docker (`docs/logs.md`), config locale `config.local.toml` pour lancer le binaire hors conteneur, et mises à jour README/CLI.

## v0.2.2 - 2025-11-21

- UI web : filtres temps réel (recherche plein texte, statut, tags) et pagination locale pour les cartes Services/Sockets, avec gestion propre du mode redacted (« non exposé »).
- CLI : options `--services-limit/--services-offset` et `--sockets-limit/--sockets-offset` pour paginer l’affichage human-readable sans toucher au JSON.
- Noyau : utilitaire générique de pagination (`PageRequest`, `Page`, `paginate_slice`) partagé entre CLI et front.
- Docs : mise à jour du guide utilisateur, du CLI et de la roadmap, plus une note dans `docs/testing.md` sur l’absence de harnais JS et les vérifications manuelles à faire sur les filtres/pagination.

## v0.2.1 - 2025-11-20

- Plugin exemple « certificates-demo » : parcourt des répertoires de PEM (override via `--probe` ou `DESCRIBE_ME_CERTS_DIR`), parse les certificats X509, calcule la validité/expiration et renvoie un résumé textuel (`certificates_summary`).
- UI web (tuile Extensions) : rendu personnalisé pour le plugin certificats, avec compteurs (PEM, certificats analysés), dossiers sondés et mise en avant des expirations les plus proches triées par ordre croissant.
- Sécurité web : les échecs d’authentification renvoient désormais une page HTML stylée (overlay, CSS inline avec nonce CSP) expliquant comment transmettre un jeton valide au lieu d’un corps brut.
- Build/infra : ajout de la cible `make vagrant-up-debian` (documentée dans `infras/README.md`) pour lancer rapidement la VM Vagrant Debian depuis la racine du projet.

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
