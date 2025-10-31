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
