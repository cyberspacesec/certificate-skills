# Build stage
FROM golang:alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags \
  "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
  -o /cert-skills ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags \
  "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
  -o /cert-skills-mcp ./cmd/mcp/

# Runtime stage for CLI
FROM alpine:3.20 AS cli

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /cert-skills /usr/local/bin/cert-skills

ENTRYPOINT ["cert-skills"]

# Runtime stage for MCP server
FROM alpine:3.20 AS mcp

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /cert-skills-mcp /usr/local/bin/cert-skills-mcp

ENTRYPOINT ["cert-skills-mcp"]
