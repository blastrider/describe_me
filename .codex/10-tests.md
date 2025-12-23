# Tests & quality gates

Baseline:
- unit tests for pure logic (parsers, precedence, security decisions)
- integration-ish tests for web wiring where feasible
- property tests for parsers/counters when it adds confidence

Mandatory after edits:
- fmt, clippy (deny warnings), full test suite

Feature matrix:
- ensure at least "no-default-features", "cli", "cli web", "cli net", "cli systemd", "all-features"

Never merge behavior changes without a regression test.
