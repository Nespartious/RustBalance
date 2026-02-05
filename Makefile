# RustBalance Makefile
# Common development tasks

.PHONY: all build check test lint fmt audit doc clean install-hooks

# Default target
all: check

# Build in release mode
build:
	cargo build --release

# Quick compile check
check:
	cargo check --all-features

# Run all tests
test:
	cargo test --all-features

# Run tests with output
test-verbose:
	cargo test --all-features -- --nocapture

# Clippy linting
lint:
	cargo clippy --all-features -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting without modifying
fmt-check:
	cargo fmt --all -- --check

# Security audit
audit:
	cargo audit

# Dependency checks (license, vulnerabilities, yanked crates)
deny:
	cargo deny check

# Build documentation
doc:
	cargo doc --no-deps --all-features

# Open documentation
doc-open:
	cargo doc --no-deps --all-features --open

# Full pre-commit check
pre-commit: fmt-check lint test

# Full CI check (what GitHub Actions runs)
ci: fmt-check lint test deny audit doc

# Clean build artifacts
clean:
	cargo clean

# Install git hooks
install-hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed"

# Install development tools
install-tools:
	cargo install cargo-deny
	cargo install cargo-audit
	cargo install cargo-watch

# Watch for changes and run tests
watch:
	cargo watch -x test

# Watch for changes and run check
watch-check:
	cargo watch -x check

# Generate test coverage (requires cargo-tarpaulin)
coverage:
	cargo tarpaulin --out Html

# Run with trace logging
run-trace:
	RUST_LOG=rustbalance=trace cargo run

# Run with debug logging
run-debug:
	RUST_LOG=rustbalance=debug cargo run

# Initialize first node (development)
init-dev:
	cargo run -- init --config ./dev/config.toml

# Join cluster (development)
join-dev:
	@echo "Usage: make join-dev TOKEN=rb1:..."
	cargo run -- join $(TOKEN)

# Show current status
status:
	cargo run -- status

# Help
help:
	@echo "RustBalance Development Commands:"
	@echo ""
	@echo "  make build       - Build release binary"
	@echo "  make check       - Quick compile check"
	@echo "  make test        - Run all tests"
	@echo "  make lint        - Run clippy"
	@echo "  make fmt         - Format code"
	@echo "  make pre-commit  - Run all pre-commit checks"
	@echo "  make ci          - Run full CI suite"
	@echo "  make doc         - Build documentation"
	@echo "  make clean       - Clean build artifacts"
	@echo ""
	@echo "  make install-hooks - Install git pre-commit hook"
	@echo "  make install-tools - Install dev tools (cargo-deny, etc)"
	@echo "  make watch       - Watch and run tests on change"
	@echo ""
	@echo "  make run-debug   - Run with debug logging"
	@echo "  make run-trace   - Run with trace logging"
