## Logging Guide

`describe_me` relies on [`tracing`](https://docs.rs/tracing) for structured logging. To keep
events consistent (especially when forwarded to journald), the crate exposes a tiny API in
`src/application/logging.rs`:

```rust
use describe_me::LogEvent;

LogEvent::Startup {
    mode: "cli".into(),
    with_services: false,
    net_listen: false,
    net_traffic: false,
    expose_all: false,
    web_expose_all: false,
    checks: &[],
}.emit();
```

### Adding or emitting a log event

1. **Pick / add a `LogEvent` variant.** Each variant encodes all required fields.
2. **Populate the variant** with `String`/`Cow<'_, str>` or primitive values.
3. **Call `.emit()`** – it routes to the correct `tracing::*` macro with consistent formatting.

When introducing a new log, extend the `LogEvent` enum and its `emit` arm. This keeps:

- field names stable across the CLI and journald,
- the set of log messages searchable in one place,
- future AI/code-review tooling aware of the available events.

### Why the helper exists

- **Consistency:** centralized message strings and structured fields avoid drift.
- **Discoverability:** developers can skim `LogEvent` to see what already exists.
- **Ergonomics:** one-line emission avoids repeating the same `info!` boilerplate.
- **Machine-friendly:** both humans and automated tools (tests, documentation generators, AIs)
  can reason about log coverage declaratively.

### When raw `tracing` macros are acceptable

Occasionally you may need ad-hoc logs inside low-level utilities. Prefer `LogEvent`, but when
adding a one-off debug statement keep it scoped, temporary, and avoid introducing new event names.

### Related files

- [`src/application/logging.rs`](../src/application/logging.rs) – implementation of `LogEvent`.
- `snapshot/roadmap_logs.md` – roadmap of currently desired log coverage.
