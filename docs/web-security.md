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

### Stockage des jetons

Depuis l’introduction de `TokenVerifier`, les jetons web ne sont plus stockés en
clair. Le fichier de configuration et l’API `WebAccess` attendent une empreinte
Argon2id (préfixe `$argon2id$`) ou bcrypt (`$2b$…`). Lors de l’autorisation, le
hash est validé puis comparé en temps constant via l’algorithme correspondant.

La CLI expose deux helpers pour générer les empreintes :

```
describe-me --hash-web-token 'mon-super-token'
describe-me --hash-web-token-stdin --hash-web-token-alg bcrypt < plain.txt
```

Les exceptions de parsing sont remontées comme `DescribeError::Config`, ce qui
permet de refuser une configuration contenant un hash invalide.

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

## Journalisation des incidents

Toutes les anomalies de sécurité (IP refusée, dépassement de quotas, verrouillage
pour dispersion de token, etc.) sont remontées via l’évènement structuré
`LogEvent::SecurityIncident`. Cela permet de brancher facilement une supervision
ou un système d’alerte :

- Le module `auth` émet des incidents lorsqu’une IP ne figure pas dans l’allowlist
  ou lorsqu’un hash de jeton ne peut être vérifié.
- `limits.rs` loggue les dépassements de rate‐limit, les verrouillages de jeton
  (quarantaine) et les violations d’affinité IP/token.
- `mod.rs` capture également les refus de permit SSE et les rejets liés au cooldown.

Un test dédié (`logs_token_affinity_violation`) vérifie qu’une violation d’affinité
génère bien une entrée exploitable.

## Durcissement côté client

L’interface web masque tous les blocs sensibles tant qu’aucun token valide n’est
présent. Le gabarit `index.html` applique la classe `blurred` au `header` et au
`main`, et le script `main.js` ne retire ce flou qu’après authentification ou
reconnexion réussie. Un test de style (`tests/ui_blur.rs`) garantit que HTML,
CSS et JS restent alignés sur ce comportement.
