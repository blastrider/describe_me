## Rust constraints

- MSRV: 1.90.0 (do not use newer language/std features).
- `#![forbid(unsafe_code)]` is enforced: do not introduce `unsafe`.
- Prefer small diffs; keep feature-gating consistent (`web`, `journald`, `config`, `net`, etc.).
- No `unwrap/expect` in production paths. Tests can use them.
