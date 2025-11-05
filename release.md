# Release checklist

1. MàJ `CHANGELOG.md` (section Unreleased -> version)
2. `cargo update`, `cargo audit`, `cargo deny check`, puis `cargo crev verify --recursive` (ajoute des reviewers de confiance avec `cargo crev trust` ; sinon la commande remontera un avertissement)
3. Génération et traçabilité :
   ```bash
   rm -f describe-me.cdx.json
   cargo cyclonedx --all-features --format json --override-filename describe-me.cdx
   mkdir -p target/sbom
   mv describe-me.cdx.json target/sbom/describe-me.cdx.json
   ```
4. `cargo test --all-features && cargo doc --no-deps --all-features`
5. Vérifier la signature des commits destinés au tag:
   ```bash
   git verify-commit HEAD
   ```
6. Tag + signature des artefacts :
   ```bash
   ver=0.1.0
   git commit -am "release v$ver"
   git tag -s v$ver -m "describe_me v$ver"
   cargo package
   pkg=target/package/describe_me-$ver.crate
   gpg --armor --detach-sign "$pkg"
   cosign sign-blob --output-signature "$pkg.cosign.sig" "$pkg"
   cosign attest --predicate target/sbom/describe-me.cdx.json --type cyclonedx "$pkg"
   git push && git push --tags
