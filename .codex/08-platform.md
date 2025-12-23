# Platform backends (linux/freebsd/windows)

- Parsing OS outputs must be:
  - locale-independent
  - resilient to missing files/binaries
  - covered by unit tests with real-ish fixtures

Linux:
- procfs parsing should be pure helpers + tests.
- systemd integration must harden systemctl invocation.

FreeBSD:
- use best-effort for optional tools; avoid hard failure where designed.

Windows:
- avoid unix-only assumptions; keep cfgs tight.
