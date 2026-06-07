#!/usr/bin/env bash
# scripts/install.sh
# Build and install cert-hacker CLI + MCP server binaries for the current platform

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
CLI_BINARY="cert-hacker"
MCP_BINARY="cert-hacker-mcp"

echo "=== Certificate Hacker Installer ==="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed. Please install Go 1.23+ from https://golang.org/dl/"
    echo "Alternatively, download pre-built binaries from the GitHub releases page."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "Detected Go version: $GO_VERSION"

# Create bin directory
mkdir -p "$BIN_DIR"

cd "$PROJECT_ROOT"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-ldflags \"-X main.version=plugin-1.0.0 -X main.commit=$COMMIT -X main.date=$DATE\""

# Build CLI binary
echo ""
echo "Building $CLI_BINARY (CLI)..."
eval "GOTOOLCHAIN=local go build $LDFLAGS -o $BIN_DIR/$CLI_BINARY cmd/main.go"

if [ $? -eq 0 ]; then
    echo "  OK: $BIN_DIR/$CLI_BINARY"
else
    echo "ERROR: CLI build failed."
    exit 1
fi

# Build MCP server binary
echo "Building $MCP_BINARY (MCP server)..."
eval "GOTOOLCHAIN=local go build $LDFLAGS -o $BIN_DIR/$MCP_BINARY cmd/mcp/main.go"

if [ $? -eq 0 ]; then
    echo "  OK: $BIN_DIR/$MCP_BINARY"
else
    echo "ERROR: MCP server build failed."
    exit 1
fi

echo ""
echo "SUCCESS: Both binaries built successfully!"
echo ""
echo "Binaries:"
echo "  CLI:       $BIN_DIR/$CLI_BINARY"
echo "  MCP:       $BIN_DIR/$MCP_BINARY"
echo ""
echo "Usage:"
echo "  CLI:       $BIN_DIR/$CLI_BINARY --help"
echo "  MCP stdio: $BIN_DIR/$MCP_BINARY -t stdio"
echo "  MCP SSE:   $BIN_DIR/$MCP_BINARY -t sse -a :8080"
echo ""
echo "For Claude Code MCP integration, add to your .mcp.json:"
echo '  {"mcpServers":{"certificate-hacker":{"command":"'"$BIN_DIR/$MCP_BINARY"'","args":["-t","stdio"]}}}'
