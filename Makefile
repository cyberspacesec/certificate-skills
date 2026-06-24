# 变量定义
BINARY_NAME=cert-skills
MCP_BINARY_NAME=cert-skills-mcp
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Go相关变量
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GO_CACHE_DIR?=$(GOBASE)/.cache/go-build
GO_MOD_CACHE_DIR?=$(GOBASE)/.cache/go-mod
GOENV=GOCACHE=$(GO_CACHE_DIR) GOMODCACHE=$(GO_MOD_CACHE_DIR)

# Make设置
MAKEFLAGS += --silent

## help: 显示帮助信息 (Show help)
help: Makefile
	echo
	echo " Choose a command for "$(BINARY_NAME)":"
	echo
	sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	echo

## prepare-go-cache: 准备可写 Go 构建缓存 (Prepare writable Go caches)
prepare-go-cache:
	echo "  >  Preparing writable Go caches..."
	mkdir -p "$(GO_CACHE_DIR)" "$(GO_MOD_CACHE_DIR)"
	set -e; \
	if [ ! -d "$(GO_MOD_CACHE_DIR)/cache/download" ]; then \
		existing_mod_cache=$$(go env GOMODCACHE 2>/dev/null || true); \
		if [ -n "$$existing_mod_cache" ] && [ "$$existing_mod_cache" != "$(GO_MOD_CACHE_DIR)" ] && [ -d "$$existing_mod_cache/cache/download" ]; then \
			cp -a "$$existing_mod_cache/." "$(GO_MOD_CACHE_DIR)/"; \
			chmod -R u+rwX "$(GO_MOD_CACHE_DIR)"; \
		fi; \
	fi

## build: 构建 CLI 应用程序 (Build CLI binary)
build: prepare-go-cache
	echo "  >  Building CLI binary..."
	$(GOENV) go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) ./cmd/

## build-mcp: 构建 MCP 服务器 (Build MCP server)
build-mcp: prepare-go-cache
	echo "  >  Building MCP server..."
	$(GOENV) go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(MCP_BINARY_NAME) ./cmd/mcp/

## build-all-binaries: 构建 CLI 和 MCP 服务器 (Build both binaries)
build-all-binaries: build build-mcp

## install: 安装依赖 (Install dependencies)
install: prepare-go-cache
	echo "  >  Installing dependencies..."
	$(GOENV) go mod download
	$(GOENV) go mod tidy

## clean: 清理构建文件 (Clean build artifacts)
clean:
	echo "  >  Cleaning build cache..."
	go clean
	rm -f $(GOBIN)/$(BINARY_NAME) $(GOBIN)/$(MCP_BINARY_NAME)

## test: 运行测试 (Run tests, skip live network tests)
test: prepare-go-cache
	echo "  >  Running tests..."
	$(GOENV) go test -short -v -race ./...

## test-live: 运行包含网络测试的完整测试 (Run all tests including live network tests)
test-live: prepare-go-cache
	echo "  >  Running all tests (including live)..."
	$(GOENV) go test -v -race ./...

## test-coverage: 运行测试并生成覆盖率报告 (Run tests with coverage)
test-coverage: prepare-go-cache
	echo "  >  Running tests with coverage..."
	$(GOENV) go test -short -race -coverprofile=coverage.out ./...
	$(GOENV) go tool cover -html=coverage.out -o coverage.html
	echo "  >  Coverage report: coverage.html"

## fmt: 格式化代码 (Format code)
fmt: prepare-go-cache
	echo "  >  Formatting code..."
	$(GOENV) go fmt ./...

## vet: 静态检查 (Run go vet)
vet: prepare-go-cache
	echo "  >  Running go vet..."
	$(GOENV) go vet ./...

## lint: 运行 linter (Run golangci-lint)
lint: prepare-go-cache
	echo "  >  Running linter..."
	$(GOENV) golangci-lint run ./...

## run: 运行应用程序 (Run the application)
run: build
	echo "  >  Running $(BINARY_NAME)..."
	$(GOBIN)/$(BINARY_NAME)

## dev: 开发模式运行 (Run in development mode)
dev: prepare-go-cache
	echo "  >  Running in development mode..."
	$(GOENV) go run ./cmd/

## build-all: 跨平台构建 (Cross-platform build)
build-all: prepare-go-cache
	echo "  >  Building for multiple platforms..."
	$(GOENV) GOOS=linux GOARCH=amd64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-amd64 ./cmd/
	$(GOENV) GOOS=darwin GOARCH=amd64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-amd64 ./cmd/
	$(GOENV) GOOS=darwin GOARCH=arm64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-arm64 ./cmd/
	$(GOENV) GOOS=windows GOARCH=amd64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-windows-amd64.exe ./cmd/

## docker-build: 构建 Docker 镜像 (Build Docker image)
docker-build:
	echo "  >  Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .

.PHONY: help prepare-go-cache build build-mcp build-all-binaries install clean test test-live test-coverage fmt vet lint run dev build-all docker-build
