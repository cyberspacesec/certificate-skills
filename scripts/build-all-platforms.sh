#!/usr/bin/env bash
# scripts/build-all-platforms.sh
# Cross-platform build for cert-hacker CLI and MCP server

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
CLI_BINARY="cert-hacker"
MCP_BINARY="cert-hacker-mcp"
VERSION="${1:-plugin-1.0.0}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-ldflags \"-X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE\""

mkdir -p "$BIN_DIR"

echo "=== Building cert-hacker for all platforms ==="
echo "Version: $VERSION"
echo ""

PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$PLATFORM"
    SUFFIX="${GOOS}-${GOARCH}"

    CLI_OUTPUT="$BIN_DIR/${CLI_BINARY}-${SUFFIX}"
    MCP_OUTPUT="$BIN_DIR/${MCP_BINARY}-${SUFFIX}"
    if [ "$GOOS" = "windows" ]; then
        CLI_OUTPUT="${CLI_OUTPUT}.exe"
        MCP_OUTPUT="${MCP_OUTPUT}.exe"
    fi

    cd "$PROJECT_ROOT"

    echo -n "Building CLI for $GOOS/$GOARCH... "
    GOOS=$GOOS GOARCH=$GOARCH eval "GOTOOLCHAIN=local go build $LDFLAGS -o $CLI_OUTPUT cmd/main.go" && echo "OK" || echo "FAILED"

    echo -n "Building MCP for $GOOS/$GOARCH... "
    GOOS=$GOOS GOARCH=$GOARCH eval "GOTOOLCHAIN=local go build $LDFLAGS -o $MCP_OUTPUT cmd/mcp/main.go" && echo "OK" || echo "FAILED"
done

echo ""
echo "Build complete. Binaries in: $BIN_DIR/"
ls -lh "$BIN_DIR/"
