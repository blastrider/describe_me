## Public API rules

- `src/api.rs` is the stable façade. Prefer adding new exports under capability modules.
- Avoid widening the flat re-exports (they are marked TODO to remove at next major).
- If you change behavior visible through api::\*: add tests and update docs/changelog if present.
