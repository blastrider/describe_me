# Mirror the CI workflow locally.

CARGO ?= cargo
FEATURES ?= --all-features
MSRV ?= 1.90.0

.PHONY: fmt fmt-check clippy test test-release doc audit deny bench ci msrv-build tools build-complete sbom supply-chain

release-complete:
	$(CARGO) build --release --all-features

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

sbom:
	cargo install cargo-cyclonedx --locked >/dev/null 2>&1 || true
	rm -f describe-me.cdx.json
	cargo cyclonedx --all-features --format json --override-filename describe-me.cdx
	mkdir -p target/sbom
	mv describe-me.cdx.json target/sbom/describe-me.cdx.json

supply-chain: audit deny
	cargo install cargo-crev --locked >/dev/null 2>&1 || true
	cargo crev repo fetch >/dev/null 2>&1 || true
	cargo crev verify --recursive || { \
		status=$$?; \
		if [ $$status -eq 255 ]; then \
			echo "cargo crev verify: aucun reviewer de confiance configuré (avertissement seulement)."; \
		else \
			exit $$status; \
		fi; \
	}
	$(MAKE) sbom

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
