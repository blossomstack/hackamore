# hackamore developer tasks

.PHONY: build test check fmt clippy run help

build: ## Build the whole workspace
	cargo build --workspace

test: ## Run all tests
	cargo test --workspace

fmt: ## Format the code
	cargo fmt --all

clippy: ## Lint with warnings denied
	cargo clippy --all-targets --all-features -- -D warnings

check: ## Pre-PR gate: fmt check + clippy + tests
	cargo fmt --all --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --workspace

run: ## Run the proxy from the example config
	cargo run -p cli --bin hackamore -- serve --config examples/config.json

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
