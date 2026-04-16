.PHONY: all build test test-coverage test-integration clean install fmt vet golangci-lint lint mithril

# Binary output directory
BIN_DIR := bin

VERSION ?= dev

all: build

build: mithril

mithril:
	@echo "Building mithril..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BIN_DIR)/mithril .

test:
	@echo "Running tests..."
	@go test -v -race ./...

test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Integration tests exercise the built `mithril` binary via exec.Command and
# are gated behind the `integration` build tag so the default `make test`
# remains fast and hermetic.
test-integration:
	@echo "Running integration tests..."
	@go test -v -tags=integration ./...

clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html

install: build
	@echo "Installing binaries to $(BIN_DIR)..."
	@chmod +x $(BIN_DIR)/*

# Development helpers
fmt:
	@go fmt ./...

vet:
	@go vet ./...

golangci-lint:
	@echo "Running golangci-lint..."
	@golangci-lint run ./...

lint: fmt vet golangci-lint
