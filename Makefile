TARGET := wasm32-wasip1
TARGET_DIR := target/$(TARGET)/release
POLICY_REF_NAME_SUFFIX := -impl

DEFINITION_NAME = $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-name 2>/dev/null || echo "api-encryption-decryption-policy")
DEFINITION_NAMESPACE = $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-namespace 2>/dev/null || echo "default")
DEFINITION_SRC_GCL_PATH = $(shell anypoint-cli-v4 pdk policy-project locate-gcl definition-src 2>/dev/null || echo "definition/gcl.yaml")
DEFINITION_GCL_PATH = $(shell anypoint-cli-v4 pdk policy-project locate-gcl definition 2>/dev/null || echo "definition/target/gcl.yaml")
CRATE_NAME = $(shell cargo anypoint get-name 2>/dev/null || echo "api_encryption_decryption_policy")
POLICY_REF_NAME = $(DEFINITION_NAME)$(POLICY_REF_NAME_SUFFIX)
ANYPOINT_METADATA_JSON = $(shell cargo anypoint get-anypoint-metadata 2>/dev/null || echo '{}')

.PHONY: setup
setup: install-cargo-anypoint ## Setup all required tools to build
	rustup target add $(TARGET)
	cargo fetch

.PHONY: build
build: build-asset-files ## Build the policy definition and implementation
	@cargo build --target $(TARGET) --release
	@SRC="$(DEFINITION_GCL_PATH)"; \
	if [ ! -f "$$SRC" ]; then SRC="definition/target/definition/gcl.yaml"; fi; \
	if [ ! -f "$$SRC" ]; then SRC="definition/target/gcl.yaml"; fi; \
	if [ ! -f "$$SRC" ]; then SRC="definition/gcl.yaml"; fi; \
	if [ ! -f "$$SRC" ]; then echo "ERROR: cannot locate generated definition gcl.yaml" >&2; exit 1; fi; \
	cp "$$SRC" "$(TARGET_DIR)/$(CRATE_NAME)_definition.yaml"
	@cargo anypoint gcl-gen -d $(DEFINITION_NAME) -n $(DEFINITION_NAMESPACE) -w $(TARGET_DIR)/$(CRATE_NAME).wasm -o $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml
	@echo $(POLICY_REF_NAME) > target/policy-ref-name.txt

.PHONY: build-asset-files
build-asset-files: $(DEFINITION_SRC_GCL_PATH)
	@anypoint-cli-v4 pdk policy-project build-asset-files --metadata '$(ANYPOINT_METADATA_JSON)'
	@if [ -d definition/target/definition ]; then \
		cp definition/target/definition/gcl.yaml definition/target/gcl.yaml 2>/dev/null || true; \
		cp definition/target/definition/metadata.yaml definition/target/metadata.yaml 2>/dev/null || true; \
		cp definition/target/definition/exchange.json definition/target/exchange.json 2>/dev/null || true; \
		cp definition/target/definition/schema.json definition/target/schema.json 2>/dev/null || true; \
	fi
	@if [ -f definition/target/gcl.yaml ] && [ ! -f definition/target/definition/gcl.yaml ]; then \
		mkdir -p definition/target/definition; \
		cp definition/target/gcl.yaml definition/target/definition/gcl.yaml 2>/dev/null || true; \
		cp definition/target/metadata.yaml definition/target/definition/metadata.yaml 2>/dev/null || true; \
		cp definition/target/exchange.json definition/target/definition/exchange.json 2>/dev/null || true; \
		cp definition/target/schema.json definition/target/definition/schema.json 2>/dev/null || true; \
	fi
	@cargo anypoint config-gen -p -m $(DEFINITION_SRC_GCL_PATH) -o src/generated/config.rs
	@python3 scripts/redact_generated_config.py src/generated/config.rs

.PHONY: test
test: ## Run unit tests
	@cargo test --lib -- --nocapture

.PHONY: publish
publish: build ## Publish a development version of the policy
	anypoint-cli-v4 pdk policy-project publish --binary-path $(TARGET_DIR)/$(CRATE_NAME).wasm --implementation-gcl-path $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml

.PHONY: release
release: build ## Publish a release version (version controlled by exchange.json)
	anypoint-cli-v4 pdk policy-project publish --binary-path $(TARGET_DIR)/$(CRATE_NAME).wasm --implementation-gcl-path $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml

.PHONY: login
login:
	@cargo login $(shell anypoint-cli-v4 pdk get-token)

.PHONY: install-cargo-anypoint
install-cargo-anypoint:
	cargo install cargo-anypoint@1.8.0

.PHONY: clean
clean:
	cargo clean

.PHONY: show-policy-ref-name
show-policy-ref-name:
	@echo $(POLICY_REF_NAME)

all: help

.PHONY: help
help: ## Shows this help
	@echo 'Usage: make <target>'
	@echo ''
	@echo 'Available targets are:'
	@echo ''
	@grep -Eh '^\w[^:]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' \
		| sort
