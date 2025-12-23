# Public API / SemVer

- `src/api.rs` is the supported import surface.
- Do not remove or rename items without explicit instruction.
- Additions:
  - prefer new modules or re-exports in `api::*`
  - keep internal modules private
- Mark unstable helpers behind `feature = "internals"` or `#[cfg(test)]`.
