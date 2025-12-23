# Security & hardening

Core principles:
- secure by default; explicit opt-in to weaken (dev mode, allow-root, etc.)
- honor precedence: CLI > config > runtime defaults
- never trust forwarded headers unless proxy is trusted
- keep allowlists strict and validated
- external commands must be hardened (env_clear, safe PATH, stable locale)

Web:
- require token OR allowlisted IPs before serving
- strict origin/CSP/security headers
- rate limit + brute force guard must remain effective across refactors

Plugins:
- validate absolute paths and confinement rules
- verify sha256 pinning when configured
- enforce timeouts
