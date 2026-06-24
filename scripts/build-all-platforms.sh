#!/usr/bin/env bash
# scripts/build-all-platforms.sh
# Cross-platform build for cert-skills CLI and MCP server

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
GO_CACHE_DIR="${GO_CACHE_DIR:-$PROJECT_ROOT/.cache/go-build}"
GO_MOD_CACHE_DIR="${GO_MOD_CACHE_DIR:-$PROJECT_ROOT/.cache/go-mod}"
CLI_BINARY="cert-skills"
MCP_BINARY="cert-skills-mcp"
VERSION="${1:-0.1.1}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=(-ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE")

mkdir -p "$BIN_DIR"
mkdir -p "$GO_CACHE_DIR" "$GO_MOD_CACHE_DIR"

EXISTING_GO_MOD_CACHE="$(go env GOMODCACHE 2>/dev/null || true)"
if [ ! -d "$GO_MOD_CACHE_DIR/cache/download" ] &&
    [ -n "$EXISTING_GO_MOD_CACHE" ] &&
    [ "$EXISTING_GO_MOD_CACHE" != "$GO_MOD_CACHE_DIR" ] &&
    [ -d "$EXISTING_GO_MOD_CACHE/cache/download" ]; then
    cp -a "$EXISTING_GO_MOD_CACHE/." "$GO_MOD_CACHE_DIR/"
    chmod -R u+rwX "$GO_MOD_CACHE_DIR"
fi

export GOCACHE="$GO_CACHE_DIR"
export GOMODCACHE="$GO_MOD_CACHE_DIR"

echo "=== Building cert-skills for all platforms ==="
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
    GOOS=$GOOS GOARCH=$GOARCH go build -trimpath "${LDFLAGS[@]}" -o "$CLI_OUTPUT" ./cmd/ && echo "OK" || echo "FAILED"

    echo -n "Building MCP for $GOOS/$GOARCH... "
    GOOS=$GOOS GOARCH=$GOARCH go build -trimpath "${LDFLAGS[@]}" -o "$MCP_OUTPUT" ./cmd/mcp/ && echo "OK" || echo "FAILED"
done

echo ""
echo "Build complete. Binaries in: $BIN_DIR/"
ls -lh "$BIN_DIR/"
