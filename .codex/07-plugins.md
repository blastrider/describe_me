# Plugins / extensions rules

- Plugins are treated as untrusted external processes.
- Always enforce:
  - absolute path expectations
  - sha256 pinning if configured
  - env allowlist (minimal)
  - timeout (kill-on-timeout)
- Plugin outputs must be parsed defensively.
- No plugin output should bypass Exposure/redaction rules in the web layer.
