## Logging rules (describe_me)

- Prefer `LogEvent::{...}.emit()` over raw tracing macros to keep field names stable.
- Do not log secrets (tokens/cookies/PII). If you must reference a token: redact/hash.
- When adding a new log: add a `LogEvent` variant rather than ad-hoc strings.
