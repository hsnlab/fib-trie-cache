# Makefile for eBPF FIB Cache

CLANG ?= clang
GO ?= go
GOIMPORTS ?= /usr/bin/goimports

# Cache size (slots per CPU). Must match CACHE_SIZE in internal/fib/types.go go:generate directive.
CACHE_SIZE ?= 65536

# Build targets
BIN := bin/fibctl
BPF_SRC := bpf/fib.c
BPF_GEN := internal/fib/bpf_x86_bpfel.go internal/fib/bpf_arm64_bpfel.go

.PHONY: all clean generate build test deps fmt install help

# Default target
all: deps generate build

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Install deps, generate BPF code, and build (default)"
	@echo "  deps      - Install Go dependencies"
	@echo "  generate  - Generate Go bindings from BPF C code"
	@echo "  build     - Build the fibctl binary"
	@echo "  clean     - Remove build artifacts"
	@echo "  test      - Run tests"
	@echo "  fmt       - Format Go and BPF code"
	@echo "  install   - Install fibctl to /usr/local/bin"
	@echo ""
	@echo "Configuration:"
	@echo "  CACHE_SIZE - Direct-mapped cache slots per CPU (default: $(CACHE_SIZE))"
	@echo "               To change, edit -DCACHE_SIZE in internal/fib/types.go"

# Install dependencies
deps:
	$(GO) mod tidy
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

# Generate Go bindings from BPF C code
generate: $(BPF_SRC)
	cd internal/fib && $(GO) generate ./...

# Build the CLI binary
build: $(BPF_GEN)
	CGO_ENABLED=0 $(GO) build -buildvcs=false -o $(BIN) ./cmd/fibctl

# Clean build artifacts
clean:
	rm -f $(BIN)
	rm -f internal/fib/bpf_*_bpfel.go internal/fib/bpf_*_bpfel.o

# Run tests
test:
	$(GO) test -v ./...

# Format code
fmt:
	$(GO) fmt ./...
	@if command -v $(GOIMPORTS) > /dev/null; then \
		$(GOIMPORTS) -w .; \
	fi
	@if command -v clang-format > /dev/null; then \
		clang-format -i $(BPF_SRC); \
	fi

# Install to system
install: build
	sudo cp $(BIN) /usr/local/bin/

# Development: regenerate and rebuild
dev: generate build

# Quick rebuild (skip generate if BPF code unchanged)
quick:
	$(GO) build -buildvcs=false -o $(BIN) ./cmd/fibctl

# Verify BPF code compiles
verify-bpf:
	$(CLANG) -O2 -g -Wall -Werror -target bpf -c $(BPF_SRC) -o /dev/null

# Print environment info
env:
	@echo "Go version: $$($(GO) version)"
	@echo "Clang version: $$($(CLANG) --version | head -1)"
	@echo "Kernel: $$(uname -r)"
	@echo "BPF filesystem: $$(mount | grep bpf || echo 'not mounted')"
