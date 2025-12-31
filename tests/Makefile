# Functional test runner for rip
# Run with: sudo make test
# Or in network namespace: sudo unshare -n make test

SHELL := /bin/bash

# Test discovery
IP_TESTS := $(wildcard ip/*.t)
TC_TESTS := $(wildcard tc/*.t)
ALL_TESTS := $(IP_TESTS) $(TC_TESTS)

# Colors
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m

.PHONY: all test build clean help ip-tests tc-tests

help:
	@echo "Functional tests for rip"
	@echo ""
	@echo "Usage:"
	@echo "  make build      - Build rip binaries (release)"
	@echo "  make test       - Run all tests (requires root or namespace)"
	@echo "  make ip-tests   - Run only ip command tests"
	@echo "  make tc-tests   - Run only tc command tests"
	@echo ""
	@echo "Running in network namespace (recommended):"
	@echo "  sudo unshare -n make test"
	@echo ""
	@echo "Available tests:"
	@for t in $(ALL_TESTS); do echo "  $$t"; done

build:
	@echo "Building rip binaries..."
	cd .. && cargo build --release

test: build $(ALL_TESTS)
	@echo ""
	@echo -e "$(GREEN)All tests completed$(NC)"

ip-tests: build $(IP_TESTS)
	@echo ""
	@echo -e "$(GREEN)IP tests completed$(NC)"

tc-tests: build $(TC_TESTS)
	@echo ""
	@echo -e "$(GREEN)TC tests completed$(NC)"

%.t: FORCE
	@echo ""
	@echo "========================================"
	@echo "Running $@"
	@echo "========================================"
	@chmod +x $@
	@bash $@ || (echo -e "$(RED)Test $@ failed$(NC)" && exit 1)

FORCE:

clean:
	@echo "Nothing to clean"

# Individual test targets
.PHONY: $(ALL_TESTS)
