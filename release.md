# Release checklist

## Automatisation du bump (release-helper)

- Lancez `make release-<patch|minor|major>` pour préparer la version. Cela appelle `scripts/release-helper`, qui :
  - vérifie que la copie de travail est propre (passez `--allow-dirty` si vous savez ce que vous faites) ;
  - incrémente `Cargo.toml` et `Cargo.lock` avec le bon SemVer ;
  - déplace la section `## Unreleased` de `CHANGELOG.md` vers `## vX.Y.Z - AAAA-MM-JJ` et ré-initialise `## Unreleased` ;
  - crée le commit `release vX.Y.Z` et un tag annoté `vX.Y.Z` (`RELEASE_SIGN_TAG=1 make release-patch` force `git tag -s`).
- Exemple complet :
  ```bash
  RELEASE_SIGN_TAG=1 make release-patch
  ```
- Vous pouvez aussi appeler directement `cargo run --manifest-path scripts/release-helper/Cargo.toml -- minor --dry-run` pour inspecter les changements générés.

## Checklist technique

1. `cargo update`, `cargo audit`, `cargo deny check`, puis `cargo crev verify --recursive` (ajoutez des reviewers de confiance avec `cargo crev trust` si besoin).
2. Génération et traçabilité :
   ```bash
   rm -f describe-me.cdx.json
   cargo cyclonedx --all-features --format json --override-filename describe-me.cdx
   mkdir -p target/sbom
   mv describe-me.cdx.json target/sbom/describe-me.cdx.json
   ```
3. `cargo test --all-features && cargo doc --no-deps --all-features`
4. Vérifier la signature des commits destinés au tag :
   ```bash
   git verify-commit HEAD
   ```
5. Packaging + signature :
   ```bash
   cargo package
   ver=$(grep '^version = ' Cargo.toml | head -n1 | cut -d '"' -f2)
   pkg=target/package/describe_me-$ver.crate
   gpg --armor --detach-sign "$pkg"
   cosign sign-blob --output-signature "$pkg.cosign.sig" "$pkg"
   cosign attest --predicate target/sbom/describe-me.cdx.json --type cyclonedx "$pkg"
   git push && git push --tags
   ```

## Workflow `integration` → `main`

1. Sur `integration`, vérifiez/complétez `CHANGELOG.md`, puis choisissez votre outil de bump :
   - recommandé : `make release-<patch|minor|major>` (automatisation locale) ;
   - alternatif : `cargo release <level> --execute --skip-push` si vous préférez l'outil [cargo-release](https://github.com/crate-ci/cargo-release) (ne combinez pas les deux).
2. Si vous devez publier sur crates.io, laissez `cargo release` pousser l'artefact (`--skip-push` pour garder la main sur la fusion) ou lancez `cargo publish` après vérification.
3. Fusionnez `integration` dans `main` (fast-forward idéalement) et poussez :
   ```bash
   git checkout main
   git merge --ff-only integration
   git push origin main
   git push origin --tags
   ```
4. Ouvrez/merguez la PR correspondante. Les status checks GitHub (job "build-test" + artefact `.deb`) doivent être verts avant la fusion.

**Checklist rapide :**

- [ ] Bump de version effectué (`make release-*` ou `cargo release <level> --execute`).  
- [ ] `cargo release`/`cargo publish` déclenché si nécessaire.  
- [ ] `integration` → `main` fusionné et poussé.  
- [ ] Tags `vX.Y.Z` poussés (`git push origin --tags`).  
