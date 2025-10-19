.PHONY: all build test bench clean install docker help.PHONY: all build test test-unit test-integration clean install fmt lint help



BINARY=pml2selinux# Variables

VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")BINARY_NAME=pml2selinux

LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"BUILD_DIR=bin

INSTALL_DIR=/usr/local/bin

all: test build

# Go commands

build:GOCMD=go

	@echo "Building $(BINARY)..."GOBUILD=$(GOCMD) build

	@go build $(LDFLAGS) -o $(BINARY) ./cliGOTEST=$(GOCMD) test

GOCLEAN=$(GOCMD) clean

test:GOFMT=$(GOCMD) fmt

	@echo "Running tests..."GOMOD=$(GOCMD) mod

	@go test -v -race -coverprofile=coverage.txt ./...

# Build flags

bench:LDFLAGS=-ldflags "-s -w"

	@echo "Running benchmarks..."

	@go test -bench=. -benchmem ./...all: fmt test build



coverage:## build: Build the CLI binary

	@go test -coverprofile=coverage.txt -covermode=atomic ./...build:

	@go tool cover -html=coverage.txt -o coverage.html	@echo "Building $(BINARY_NAME)..."

	@mkdir -p $(BUILD_DIR)

lint:	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cli

	@echo "Running linter..."	@echo "✓ Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

	@golangci-lint run --timeout=5m

## test: Run all tests

clean:test: test-unit test-integration

	@echo "Cleaning..."	@echo "✓ All tests passed"

	@rm -f $(BINARY) coverage.txt coverage.html

	@rm -rf output/## test-unit: Run unit tests

test-unit:

install: build	@echo "Running unit tests..."

	@echo "Installing to /usr/local/bin..."	$(GOTEST) -v ./compiler/...

	@sudo cp $(BINARY) /usr/local/bin/	$(GOTEST) -v ./mapping/...

	$(GOTEST) -v ./models/...

docker-build:	$(GOTEST) -v ./selinux/...

	@echo "Building Docker image..."

	@docker build -t cici0602/$(BINARY):$(VERSION) .## test-integration: Run integration tests

test-integration:

docker-run:	@echo "Running integration tests..."

	@docker run --rm -v $(PWD):/workspace cici0602/$(BINARY):$(VERSION)	$(GOTEST) -v ./integration_tests/...



examples:## test-coverage: Run tests with coverage

	@echo "Running examples..."test-coverage:

	@./$(BINARY) compile -m examples/httpd/httpd_model.conf -p examples/httpd/httpd_policy.csv -o output/httpd	@echo "Running tests with coverage..."

	@./$(BINARY) compile -m examples/nginx/nginx_model.conf -p examples/nginx/nginx_policy.csv -o output/nginx	$(GOTEST) -cover -coverprofile=coverage.out ./...

	@./$(BINARY) compile -m examples/postgresql/postgresql_model.conf -p examples/postgresql/postgresql_policy.csv -o output/postgresql	$(GOCMD) tool cover -html=coverage.out -o coverage.html

	@echo "✓ Coverage report generated: coverage.html"

help:

	@echo "Available targets:"## clean: Clean build artifacts

	@echo "  all          - Run tests and build"clean:

	@echo "  build        - Build binary"	@echo "Cleaning..."

	@echo "  test         - Run tests"	$(GOCLEAN)

	@echo "  bench        - Run benchmarks"	rm -rf $(BUILD_DIR)

	@echo "  coverage     - Generate coverage report"	rm -f coverage.out coverage.html

	@echo "  lint         - Run linter"	rm -rf /tmp/selinux_output /tmp/nginx_output

	@echo "  clean        - Clean build artifacts"	@echo "✓ Clean complete"

	@echo "  install      - Install to /usr/local/bin"

	@echo "  docker-build - Build Docker image"## install: Install the binary to system

	@echo "  docker-run   - Run in Docker"install: build

	@echo "  examples     - Run all examples"	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."

	@cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/
	@chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✓ Installed: $(INSTALL_DIR)/$(BINARY_NAME)"

## uninstall: Remove installed binary
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✓ Uninstalled"

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...
	@echo "✓ Code formatted"

## lint: Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --verbose; \
	else \
		echo "⚠ golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## tidy: Tidy Go modules
tidy:
	@echo "Tidying modules..."
	$(GOMOD) tidy
	@echo "✓ Modules tidied"

## run-httpd: Compile httpd example
run-httpd: build
	@echo "Compiling httpd example..."
	@mkdir -p output
	./$(BUILD_DIR)/$(BINARY_NAME) compile \
		-m examples/httpd/httpd_model.conf \
		-p examples/httpd/httpd_policy.csv \
		-o output/httpd
	@echo ""
	@echo "Generated files:"
	@ls -lh output/httpd/

## run-nginx: Compile nginx example
run-nginx: build
	@echo "Compiling nginx example..."
	@mkdir -p output
	./$(BUILD_DIR)/$(BINARY_NAME) compile \
		-m examples/nginx/nginx_model.conf \
		-p examples/nginx/nginx_policy.csv \
		-o output/nginx
	@echo ""
	@echo "Generated files:"
	@ls -lh output/nginx/

## run-ssh: Compile ssh example
run-ssh: build
	@echo "Compiling ssh example..."
	@mkdir -p output
	./$(BUILD_DIR)/$(BINARY_NAME) compile \
		-m examples/ssh/ssh_model.conf \
		-p examples/ssh/ssh_policy.csv \
		-o output/ssh
	@echo ""
	@echo "Generated files:"
	@ls -lh output/ssh/

## run-all: Compile all examples
run-all: run-httpd run-nginx run-ssh
	@echo "✓ All examples compiled"

## validate: Validate all examples
validate: build
	@echo "Validating all examples..."
	@./$(BUILD_DIR)/$(BINARY_NAME) validate -m examples/httpd/httpd_model.conf -p examples/httpd/httpd_policy.csv
	@./$(BUILD_DIR)/$(BINARY_NAME) validate -m examples/nginx/nginx_model.conf -p examples/nginx/nginx_policy.csv
	@./$(BUILD_DIR)/$(BINARY_NAME) validate -m examples/ssh/ssh_model.conf -p examples/ssh/ssh_policy.csv
	@echo "✓ All examples validated"

## help: Show this help message
help:
	@echo "PML-to-SELinux Compiler - Makefile Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
