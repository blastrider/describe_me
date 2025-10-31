# Web Security Architecture

Ce document résume la structure du module `application::web::security` et les
outils réutilisables introduits pour gérer l’authentification et le
rate-limiting.

## Découpage par responsabilités

Le dossier `src/application/web/security/` expose plusieurs sous-modules qui se
complètent :

- `auth.rs` : construit la requête d’authentification (`AuthRequest`), extrait
  les en-têtes (token Bearer ou `x-describe-me-token`) et applique la logique de
  redaction selon la configuration.
- `limits.rs` : regroupe les politiques (`SecurityPolicy`, `RoutePolicy`,
  `BruteForcePolicy`) et la coordination principale (`SecurityState`) qui
  orchestre rate-limiting, backoff et suivi des échecs.
- `sse.rs` : isole la gestion des connexions SSE (permis de connexion,
  fingerprint des tokens, slots actifs).

Ce découpage permet d’écrire des tests ciblés (par exemple sur `authorize`,
`verify_token`, `enforce_rate_limits` ou `acquire_permit`) sans dépendre d’un
gros bloc monolithique.

## Trackers réutilisables

`limits.rs` fournit trois structures génériques pour encapsuler les anciens
`Mutex<HashMap<…>>` :

- `RateLimiter<K>` : compteur à fenêtre mobile pour limiter les requêtes par IP
  ou par token.
- `FailureTracker<K>` : suit les échecs successifs et applique le backoff
  exponentiel configuré.
- `TokenSpreadTracker` : détecte la dispersion des échecs d’authentification
  d’un même token sur plusieurs IP pour appliquer des mesures de quarantaine.

Chaque tracker fournit des méthodes `register`, `existing_block` et `clear`,
réduisant la duplication et clarifiant la lecture de `SecurityState`.

## Tests ciblés

Les tests unitaires couvrent désormais les helpers extraits (`auth.rs`,
`limits.rs`, `sse.rs`). Selon les besoins, on peut compléter par des tests
directs sur les trackers pour verrouiller les comportements de fenêtre glissante
ou de backoff.
