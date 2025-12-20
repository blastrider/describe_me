## Security baseline

- Treat all inputs as untrusted (HTTP, env, filesystem, plugin outputs).
- Bound everything:
  - request body sizes
  - pagination limits
  - timeouts for I/O (network/process)
  - output sizes for external commands/plugins
- Prefer allowlists over blocklists.
- Forwarded headers:
  - do not trust `Forwarded` / `X-Forwarded-*` unless there is an explicit trusted-proxy mechanism
- Filesystem:
  - canonicalize before use
  - prevent traversal/symlink escapes
  - keep confinement rules strict
- Crypto:
  - use vetted crates only; no custom crypto
  - never roll your own tokens/signatures
