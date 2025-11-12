# Convenience Makefile to forward common targets to repository root

.PHONY: fmt ci release-complete help

ROOT := $(abspath $(CURDIR)/..)

fmt:
	$(MAKE) -C $(ROOT) fmt

ci:
	$(MAKE) -C $(ROOT) ci

release-complete:
	$(MAKE) -C $(ROOT) release-complete

help:
	@echo "Targets forwarded to repo root:"
	@echo "  make fmt              -> cargo fmt"
	@echo "  make ci               -> fmt-check, clippy, test, doc, audit, deny, bench"
	@echo "  make release-complete -> cargo build --release --all-features"
