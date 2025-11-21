# Tests, Benchmarks & Fuzz

Le dépôt inclut plusieurs niveaux de tests pour garantir la stabilité du
collecteur.

## Tests unitaires (in-band)

- Modules `application/web/security/` : tests ciblés pour
  l’autorisation, le rate limiting, les SSE slots.
- `application/web/template.rs` : snapshots implicites via les tests de
  sécurité.

## Dossier `tests/`

Scénarios exécutés via `cargo test` (integration tests) :

- `smoke.rs` : capture basique du snapshot et vérification JSON.
- `disk_smoke.rs` : agrégat disque et partitions.
- `systemd_parse_prop.rs` : parsing des sorties `systemctl`.

## Benchmarks

`benches/snapshot_bench.rs` (criterion) mesure le temps de capture d’un
snapshot complet, utile pour suivre les régressions liées à la collecte.

## Fuzzing

`fuzz/` contient une cible `parse_systemd_line` (libFuzzer + cargo-fuzz)
qui renforce la robustesse du parsing `systemctl`.

## Lint & format

- `cargo fmt` garantit le style.
- `cargo clippy --all-targets --all-features -D warnings` garde le code
  propre (testé lors du refactoring).

## Front (UI web)

Il n’y a pas encore de harnais de tests automatisés pour les assets
JavaScript (UI SSE). Les filtres/tri/pagination des services et sockets
sont purement côté client et doivent être vérifiés manuellement :

- lancer `describe-me` en mode web avec exposition des services/sockets
  (`--web-expose-services --web-expose-network-traffic` si besoin),
  puis vérifier la barre de recherche, le select de statut et les puces
  de tags dans la tuile Services ; idem pour la tuile Sockets.
- tester la pagination (précédent/suivant) et le message « non exposé »
  lorsque `services_running`/`listening_sockets` ne sont pas présents
  dans le SnapshotView (exposure redacted).

Pour ajouter des tests auto JS, prévoir l’introduction d’un runner Node
(`node --test` + jsdom ou Vitest/Jest) et extraire les fonctions pures
de filtrage/tri dans un module commun. Aucune dépendance Node n’est
encore versionnée dans ce dépôt, il faudra donc ajouter le tooling le
moment venu.
