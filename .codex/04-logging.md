# Logging & observability

- Use structured logging (tracing / LogEvent style).
- Do not log secrets (tokens, session ids, raw auth headers).
- For external command failures:
  - include command name + status + stderr (sanitized)
- Use log levels consistently:
  - debug: skip/optional sources
  - warn: degraded behavior
  - error: actionable failures
