# Mirror the CI workflow locally.

CARGO ?= cargo
FEATURES ?= --all-features
MSRV ?= 1.90.0
DEB_FEATURES ?= cli web config systemd net journald
DEB_FEATURE_ARGS ?= --features "$(DEB_FEATURES)"
DEB_USE_CONTAINER ?= 1

RELEASE_SIGN_TAG ?= 0
RELEASE_HELPER ?= cargo run --quiet --manifest-path scripts/release-helper/Cargo.toml --
RELEASE_SIGN_FLAG :=
ifneq ($(RELEASE_SIGN_TAG),0)
RELEASE_SIGN_FLAG := --sign-tag
endif

.PHONY: all deb fmt fmt-check clippy test test-release doc audit deny bench ci msrv-build tools build-complete sbom supply-chain release-patch release-minor release-major build-plugins vagrant-up-debian

all: deb

PLUGIN_MANIFESTS := plugin-examples/certificates/Cargo.toml
PLUGIN_TARGET_DIR := $(abspath target)
ifdef CARGO_TARGET_DIR
PLUGIN_TARGET_DIR := $(CARGO_TARGET_DIR)
endif

build-plugins:
	@if [ -n "$(strip $(PLUGIN_MANIFESTS))" ]; then \
		for manifest in $(PLUGIN_MANIFESTS); do \
			echo "[plugin] building $$manifest"; \
			CARGO_TARGET_DIR="$(PLUGIN_TARGET_DIR)" $(CARGO) build --release --manifest-path $$manifest; \
		done; \
	else \
		echo "[plugin] no plugin manifests configured"; \
	fi

release-complete:
	$(CARGO) build --release --all-features
	$(MAKE) build-plugins

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

ci: fmt-check clippy test test-release doc audit deny bench build-plugins

msrv-build:
	cargo +$(MSRV) build -Z unstable-options

tools:
	@for tool in cargo-audit cargo-deny; do \
		if ! command -v $$tool >/dev/null 2>&1; then \
			cargo install $$tool --locked; \
		fi; \
	done

ifeq ($(DEB_USE_CONTAINER),1)
deb:
	DEB_FEATURES="$(DEB_FEATURES)" ./scripts/deb-bookworm-build.sh
else
deb: build-plugins
	@if ! command -v cargo-deb >/dev/null 2>&1; then \
		cargo install cargo-deb --locked; \
	fi
	$(CARGO) build --release $(DEB_FEATURE_ARGS)
	$(CARGO) deb $(DEB_FEATURE_ARGS) --no-build
endif

deb-bookworm:
	DEB_FEATURES="$(DEB_FEATURES)" ./scripts/deb-bookworm-build.sh

release-patch:
	$(RELEASE_HELPER) patch $(RELEASE_SIGN_FLAG)

release-minor:
	$(RELEASE_HELPER) minor $(RELEASE_SIGN_FLAG)

release-major:
	$(RELEASE_HELPER) major $(RELEASE_SIGN_FLAG)

vagrant-up-debian:
	cd infras && vagrant up debian
