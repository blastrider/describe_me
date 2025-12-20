## Platform backends (linux/freebsd/systemd/journald/net)

- Keep OS-specific code isolated in platform/infrastructure modules.
- Prefer feature gates per OS/backend; do not regress cross-platform builds.
- Parsers (procfs, net tables, etc.):
  - validate against real-like samples
  - avoid self-encoded-only tests
- Use robust error handling:
  - missing optional files should be handled gracefully
  - failures should emit structured logs and allow partial snapshots when safe
- Do not assume systemd/journald exists; keep fallbacks where applicable.
