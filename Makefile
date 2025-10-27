# Mirror the CI workflow locally.

CARGO ?= cargo
FEATURES ?= --all-features
MSRV ?= 1.90.0

.PHONY: fmt fmt-check clippy test test-release doc audit deny bench ci msrv-build tools

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt -- --check

clippy:
	$(CARGO) clippy --all-targets $(FEATURES) -- -D warnings

test:
	$(CARGO) test $(FEATURES)

test-release:
	$(CARGO) test --release $(FEATURES)

doc:
	$(CARGO) doc --no-deps $(FEATURES)

audit:
	cargo install cargo-audit --locked >/dev/null 2>&1 || true
	cargo audit

deny:
	cargo install cargo-deny --locked >/dev/null 2>&1 || true
	cargo deny check

bench:
	$(CARGO) bench --no-run $(FEATURES)

ci: fmt-check clippy test test-release doc audit deny bench

msrv-build:
	cargo +$(MSRV) build -Z unstable-options

tools:
	@for tool in cargo-audit cargo-deny; do \
		if ! command -v $$tool >/dev/null 2>&1; then \
			cargo install $$tool --locked; \
		fi; \
	done
