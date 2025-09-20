# 变量定义
BINARY_NAME=cert-hacker
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD)
DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Go相关变量
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard *.go)

# Make设置
MAKEFLAGS += --silent

## help: 显示帮助信息
help: Makefile
	echo
	echo " Choose a command run in "$(BINARY_NAME)":"
	echo
	sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	echo

## build: 构建应用程序
build:
	echo "  >  Building binary..."
	go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) cmd/main.go

## install: 安装依赖
install:
	echo "  >  Installing dependencies..."
	go mod download
	go mod tidy

## clean: 清理构建文件
clean:
	echo "  >  Cleaning build cache..."
	go clean
	rm -f $(GOBIN)/$(BINARY_NAME)

## test: 运行测试
test:
	echo "  >  Running tests..."
	go test -v ./...

## test-coverage: 运行测试并生成覆盖率报告
test-coverage:
	echo "  >  Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## fmt: 格式化代码
fmt:
	echo "  >  Formatting code..."
	go fmt ./...

## lint: 代码检查
lint:
	echo "  >  Running linter..."
	golangci-lint run

## run: 运行应用程序
run: build
	echo "  >  Running $(BINARY_NAME)..."
	$(GOBIN)/$(BINARY_NAME)

## dev: 开发模式运行
dev:
	echo "  >  Running in development mode..."
	go run cmd/main.go

## build-all: 跨平台构建
build-all:
	echo "  >  Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-amd64 cmd/main.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-amd64 cmd/main.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-arm64 cmd/main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-windows-amd64.exe cmd/main.go

## docker-build: 构建Docker镜像
docker-build:
	echo "  >  Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .

.PHONY: help build install clean test test-coverage fmt lint run dev build-all docker-build
