## Architecture rules

- Keep modules single-responsibility; avoid “god modules”.
- Separate concerns:
  - web handlers: parse/validate + call service + map error to response
  - services: business logic, orchestration
  - collectors: system snapshot collection; no web concerns
  - infra: OS-specific code, I/O, process exec
- Keep boundaries explicit via traits/interfaces where it reduces duplication.
- Avoid cyclic dependencies; prefer dependency direction: web -> app -> infra.
