# Chaîne supply-chain & SAST

Ce dépôt intègre plusieurs garde-fous pour limiter les risques liés aux dépendances et à la chaîne de build. Les commandes suivantes sont automatisées dans la CI (`supply-chain` job) mais restent exécutables en local :

1. **Détection de vulnérabilités connues**  
   ```bash
   cargo audit
   cargo deny check
   ```
   `cargo deny` s’appuie sur `deny.toml` (licences, bans, advisories). Pense à adapter la section `[advisories]` si une dépendance spécifique nécessite un traitement particulier.

2. **Revue pair-à-pair des crates (cargo-crev)**  
   ```bash
   cargo crev verify --recursive
   ```
   Sans reviewers de confiance (`cargo crev trust` / `cargo crev repo fetch trusted`), la vérification se termine avec un statut d'avertissement (la CI le signale sans l'échouer).
   Initialise ton profil si nécessaire : `cargo crev id new`. Tu peux importer les trusts publics via `cargo crev repo fetch trusted`. Les preuves locales sont stockées dans `~/.config/crev`.

3. **SBOM CycloneDX**  
   ```bash
   rm -f describe-me.cdx.json
   cargo cyclonedx --all-features --format json --override-filename describe-me.cdx
   mkdir -p target/sbom
   mv describe-me.cdx.json target/sbom/describe-me.cdx.json
   ```
   Le SBOM est publié comme artefact CI. Pour des releases officielles, signe-le (GPG/cosign) et attache-le aux artefacts.

4. **Signature et vérification Git**  
   - Vérifie systématiquement la signature des commits : `git verify-commit HEAD`.
   - Signe les tags de release : `git tag -s vX.Y.Z`.

5. **Signature des artefacts**  
   Les releases officielles doivent être signées :
   ```bash
   pkg=target/package/describe_me-$ver.crate
   gpg --armor --detach-sign "$pkg"
   cosign sign-blob --output-signature "$pkg.cosign.sig" "$pkg"
   cosign attest --predicate target/sbom/describe-me.cdx.json --type cyclonedx "$pkg"
   ```
   Conserve les clés (GPG/cosign) dans un coffre (ex: `actions/runner` via secrets GitHub). Les attestations cosign relient le SBOM à l’artefact.

## Outils SAST complémentaires

- `cargo clippy --all-targets --all-features -- -D warnings` (déjà exécuté dans la CI).
- `cargo fmt --all`.
- Pour les commandes Rust “lentes”, active `RUSTSEC_LOG=warn` afin de diagnostiquer les erreurs réseau.

## Intégration CI

Le job GitHub Actions `supply-chain` installe les outils (`cargo-audit`, `cargo-deny`, `cargo-crev`, `cargo-cyclonedx`), vérifie les signatures Git (push), génère le SBOM et le publie comme artefact. Toute régression (vulnérabilité, licence interdite, vérification crev échouée) cassera la CI.
