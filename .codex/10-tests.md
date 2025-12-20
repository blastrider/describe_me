## Tests / fuzz / internals

- Any non-trivial change must include tests (unit/integration).
- Security-critical changes must include regression tests.
- Avoid flaky timing assertions; prefer deterministic tests.
- If fuzz targets exist:
  - keep them compiling
  - update signatures when internal APIs change
- For parsing: include “real” sample lines/data in fixtures.
