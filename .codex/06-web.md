# Web (Axum/SSE) rules

- Keep router wiring thin; handlers call application services.
- Validate query params and body payloads; return typed WebError.
- Respect exposure/redaction:
  - redacted mode must not leak sensitive fields
  - paranoid mode may restrict endpoints

Access control:
- preserve allowlist/trusted proxy behavior and ordering
- never accept X-Forwarded-* unless proxy matches trusted rules
- keep session cookie settings strict; dev flags must be explicit
