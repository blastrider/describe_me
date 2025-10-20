# Release checklist

1. MàJ `CHANGELOG.md` (section Unreleased -> version)
2. `cargo update` puis `cargo audit` / `cargo deny check`
3. `cargo test --all-features && cargo doc --no-deps --all-features`
4. Tag:
   ```bash
   ver=0.1.0
   git commit -am "release v$ver"
   git tag -a v$ver -m "decribe_me v$ver"
   git push && git push --tags