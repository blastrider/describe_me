# Scope & repo intent

describe_me is:
- a Rust library + CLI to capture "system snapshots"
- optional web UI/API (Axum + SSE)
- optional extensions/plugins (separate binaries, pinned)

Out of scope unless requested:
- large refactors touching many modules without tests
- changing security defaults
- changing public API surface

Key constraints:
- feature-gated build (cli/web/config/net/systemd/internals)
- cross-platform codepaths (linux/freebsd/windows)
- security-sensitive boundaries (web auth, allowlists, origin/proxy trust)

Review workflow:
- For code reviews, check `snapshot/REVUE - INNLOG - 27-12-2025.md` first and avoid duplicate recommendations.
