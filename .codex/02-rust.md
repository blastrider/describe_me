# Rust coding guidelines

- Keep ownership simple. Prefer borrowing and builders.
- Return domain errors from library code; reserve anyhow for binaries/orchestration.
- Avoid panics in production paths.
- Avoid unnecessary allocations and clones. Prefer:
  - `&str` over `String` when possible
  - `Cow<'a, str>` when you need optional ownership
  - `Arc` for shared immutable data
- Prefer `match` + exhaustiveness over chains of `if`.
- Use `#[cfg(...)]` locally (small scopes) to reduce compile noise.
