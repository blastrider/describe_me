# agent.md — describe_me (Codex agent rules)

This repo is security-sensitive (web auth, allowlists, proxies, plugins, parsing OS surfaces).
Treat every change as potentially breaking or weakening defenses.

## 0) Non-negotiables

- No unsafe code.
- No "tests pass" claims unless you actually ran them and captured output.
- Prefer small, reviewable diffs. Keep behavior stable unless the task explicitly changes it.
- Respect feature gating: code must compile with different feature sets and targets.

## 1) What to read first

When you touch:
- CLI / run orchestration: `src/bin/describe_me/run/*`
- Public API: `src/api.rs` (only stable surface)
- Web: `src/application/web/*`
- Platform backends: `src/infrastructure/*`
- Security: `src/security.rs` + web security modules
- Plugins: `describe_me_plugin_sdk` + domain plugin config

When doing a code review:
- Read `snapshot/REVUE - INNLOG - 27-12-2025.md` first to avoid duplicating recommendations.
- When you address an item from `snapshot/REVUE - INNLOG - 27-12-2025.md`, strike through the line to mark it done.
- Marquer toutes les revues (fichiers dont le nom commence par `REVUE`) avec un statut « à checker » dans vos notes/réponses tant qu’elles ne sont pas soldées.

## 2) Output contract (what you must produce)

For every change request, output:

1) **Intent**: 2–5 bullets of what you changed (no marketing).
2) **Patch**: exact file edits.
3) **Risk notes**: any security / compat / cfg gating risk.
4) **Tests run**: commands + summarized results.

If you could not run a command, state it explicitly and why (missing toolchain/target/etc.).

## 3) Mandatory local verification (run after code edits)

Tell the user to run instead of running them by yourself, in this order, and do not skip Clippy (fix issues before launching the full test matrix):

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`

Then run a feature matrix sanity check (fast but catches cfg breaks):

- `cargo test --workspace --no-default-features`
- `cargo test --workspace --features "cli web config net systemd"`
- `cargo test --workspace --features "internals"`

If the repo has multiple crates, include `--workspace` everywhere.

## 4) Rust style rules (idiomatic, maintainable)

- Prefer expressive types and invariants; avoid "stringly typed" unless boundary parsing.
- Error handling:
  - Library code: return `DescribeError` (or domain error) and preserve context.
  - Binaries/CLI: `anyhow::Result` is fine for orchestration.
- No `.unwrap()` / `.expect()` in non-test code unless guarded by invariants and justified.
- Avoid cloning large data; prefer borrowing (`&str`, slices, `Arc`) and builders.
- Keep modules small and single-purpose; use `mod.rs` only as a router when needed.

### Rust official guidelines (idiomatic defaults)

- Follow Rust official conventions as the default (naming, patterns, iterator usage, error shapes).
- API design: `new()` should not fail; use `try_new()` / `from_*()` / `parse()` when validation can fail.
- Prefer enums/newtypes over booleans/strings to encode invariants (“make invalid states unrepresentable”).
- Keep `pub` minimal; design public surfaces intentionally (esp. `src/api.rs`).
- Prefer borrowing (`&T`, `&str`, slices) and iterators; avoid manual indexing when not required.

### Maintainability (human-first)

- Keep files/modules focused: one responsibility per file/module; split when scope grows.
- Keep functions readable: shallow nesting, early returns, extract helpers for complex branches.
- Avoid cleverness: prefer explicit, boring code over macro-heavy or overly generic abstractions.
- Prefer cohesive types over global/shared mutable state; document invariants when state is required.
- Keep changes reviewable: minimal diff surface, localized edits, stable behavior unless requested.


## 5) Security rules

- Never weaken access control defaults.
- Preserve precedence rules for configuration sources (CLI > config > runtime defaults).
- External commands must be hardened:
  - absolute path when applicable
  - `env_clear()`
  - minimal `PATH`
  - controlled locale (`LC_ALL=C`) where parsing is involved
- Token material:
  - never log raw tokens
  - accept only hashed tokens in config where designed
- Be strict on proxy trust: never accept forwarded headers unless the proxy is trusted.

## 6) Web rules (Axum)

- Every handler must:
  - validate inputs
  - return typed errors (no ad-hoc strings)
  - respect Exposure/redaction modes
- Keep HTTP-only logic in the web layer; business logic lives in application/services.

## 7) Tests policy

- Add unit tests for:
  - parsing (happy + edge cases)
  - precedence / ordering (config/CLI/runtime)
  - security decisions (allowlist/proxy/origin)
- Prefer pure helpers returning values over helpers that exit/process-terminate.
- When changing behavior, add regression tests first.

## 8) Public API & SemVer

- `src/api.rs` is the stable facade. Don’t break it without explicit instruction.
- New capabilities: add behind modules/features and keep old paths working if possible.
- Décider une règle : pas de renaming public (on déplace, on pub use).

## 9) Documentation & comments

- Comments only for non-obvious rationale, security invariants, or platform quirks.
- Keep doc comments short and accurate.
- Pour chaque ajout à impact significatif (sécurité, orchestration, comportement runtime), produire une documentation associée (README/docs/CHANGELOG) expliquant l’intention, l’usage et les risques.
- Quand tu touches aux singletons/globales (metadata store, state_dir override, history identity, caches), nettoie toujours l’état global dans les tests (`reset_metadata_store_for_tests`, `clear_state_dir_override_for_tests`, etc.), puis rerun au minimum `cargo test --all-targets --all-features` pour éviter de laisser des verrous empoisonnés ou des caches incohérents.
