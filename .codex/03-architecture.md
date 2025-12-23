# Architecture rules

Layers:
- domain: types, config structures, errors
- application: capture services, history, exposure/redaction rules
- infrastructure: platform backends (systemctl, procfs, pkg tools, sysinfo, storage)
- web (feature): Axum routing, SSE, auth, headers, caching
- bin: CLI wiring, config resolution, render, health checks

Rules:
- keep business logic out of web handlers
- keep parsing pure and unit-testable
- move `process::exit` to binary boundary only
