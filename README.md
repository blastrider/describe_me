# decribe_me

> **Description (≤30 mots)**  
Décrit rapidement CPU, RAM, OS, uptime et services d’un serveur pour un diagnostic express et scriptable.

**Résumé (≤40 mots)**  
Bibliothèque Rust sûre (aucun `unsafe` public) basée sur `sysinfo`. Option Linux `systemd` pour lister les services. Un petit CLI imprime le snapshot en JSON.

## MSRV
- `MSRV = 1.90.0` (fixée dans `[package.metadata]` et testée en CI)

## Utilisation (lib)
```rust
use decribe_me::SystemSnapshot;
let snap = SystemSnapshot::capture()?;
println!("Host: {}", snap.hostname);
CLI (optionnel)
bash
Copier le code
cargo run --features "cli systemd" --bin decribe-me -- --with-services
Développement
bash
Copier le code
cargo fmt && cargo clippy --all-targets -- -D warnings
cargo test --all-features
cargo bench --no-run
Checklist conformité
 MSRV 1.90.0

 fmt en CI

 clippy -D warnings en CI

 Erreurs thiserror (lib) / anyhow (CLI)

 Pas d’unwrap hors tests

 Doctests/Exemples/Intégration

 cargo-audit / cargo-deny

 Features additives (serde, systemd, cli, internals pour tests)

 CHANGELOG à compléter avant release

Références
Rust API Guidelines — https://rust-lang.github.io/api-guidelines/

Clippy Lints — https://rust-lang.github.io/rust-clippy/master/index.html

ANSSI Secure Rust Guide — https://anssi-fr.github.io/rust-guide/

Rust Performance Book — https://nnethercote.github.io/perf-book/

Miri — https://github.com/rust-lang/miri

yaml
Copier le code

---

### `CHANGELOG.md`
```markdown
# Changelog

## [0.1.0] - 2025-10-20
- Première version : snapshot CPU/RAM/OS/uptime/load via `sysinfo`.
- Feature `systemd` : liste des services en cours d’exécution.
- CLI optionnel `decribe-me` (JSON).