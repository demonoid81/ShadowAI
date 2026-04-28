# PR-O1: Production-grade Dockerfile.
#
# Build targets:
#   default      → core shadowai binary (Apache 2.0)
#   enterprise   → enterprise shadowai binary (-tags enterprise)
#
# Usage:
#   docker build -t shadowai:latest .
#   docker build --build-arg BUILD_TAGS=enterprise -t shadowai:enterprise .
#
# The migrate binary is built alongside shadowai and lives at
# /usr/local/bin/migrate — use as an init container:
#   command: [migrate, --dir, /migrations, --enterprise-dir, /migrations-enterprise]

FROM golang:1.25-alpine AS builder

# Build argument for enterprise build.
ARG BUILD_TAGS=""

WORKDIR /app

# Download dependencies separately for layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build shadowai (with optional enterprise tags).
RUN CGO_ENABLED=0 go build \
    -tags "${BUILD_TAGS}" \
    -ldflags="-w -s" \
    -o /shadowai \
    ./cmd/shadowai

# Build migration runner (always without enterprise tags — runs against DB).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /migrate \
    ./cmd/migrate

# Build audit-verify CLI for ops tooling.
RUN CGO_ENABLED=0 go build \
    -tags "${BUILD_TAGS}" \
    -ldflags="-w -s" \
    -o /audit-verify \
    ./cmd/audit-verify

# Build audit-export-evidence CLI (PR-O4.1: evidence bundle export).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /audit-export-evidence \
    ./cmd/audit-export-evidence

# Build evidence-upload CLI (PR-O4.2: S3-compatible bundle upload).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /evidence-upload \
    ./cmd/evidence-upload

# Build audit-evidence-report CLI (PR-O4.4: S3 retention audit report).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /audit-evidence-report \
    ./cmd/audit-evidence-report

# Build audit-collect-evidence CLI (PR-SOC2.1: quarterly compliance evidence package).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /audit-collect-evidence \
    ./cmd/audit-collect-evidence

# Build audit-access-review CLI (PR-SOC2.3: access review evidence report).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /audit-access-review \
    ./cmd/audit-access-review

# Build audit-byok-sweep CLI (BYOK2.1: legacy audit payload re-encryption).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /audit-byok-sweep \
    ./cmd/audit-byok-sweep

# Build firewall-corpus-verify CLI (F8.1: semantic_v2 promotion gate).
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /firewall-corpus-verify \
    ./cmd/firewall-corpus-verify

# PROD1: CLI для deployment-specific go/no-go validation.
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o /shadowai-prod-validate \
    ./cmd/shadowai-prod-validate

# ---------------------------------------------------------------------------
# Runtime image
# ---------------------------------------------------------------------------
FROM alpine:3.21

# ca-certificates: needed for TLS calls to LLM providers and IdPs.
# wget: used by HEALTHCHECK.
RUN apk add --no-cache ca-certificates wget && \
    addgroup -g 10001 shadowai && \
    adduser -u 10001 -G shadowai -D -H shadowai

COPY --from=builder /shadowai               /usr/local/bin/shadowai
COPY --from=builder /migrate                /usr/local/bin/migrate
COPY --from=builder /audit-verify           /usr/local/bin/audit-verify
COPY --from=builder /audit-export-evidence  /usr/local/bin/audit-export-evidence
COPY --from=builder /evidence-upload        /usr/local/bin/evidence-upload
COPY --from=builder /audit-evidence-report   /usr/local/bin/audit-evidence-report
COPY --from=builder /audit-collect-evidence  /usr/local/bin/audit-collect-evidence
COPY --from=builder /audit-access-review    /usr/local/bin/audit-access-review
COPY --from=builder /audit-byok-sweep       /usr/local/bin/audit-byok-sweep
COPY --from=builder /firewall-corpus-verify /usr/local/bin/firewall-corpus-verify
COPY --from=builder /shadowai-prod-validate /usr/local/bin/shadowai-prod-validate

# SQL migrations baked into the image so the migrate init container
# doesn't need a volume mount.
COPY migrations/             /migrations/
COPY migrations-enterprise/  /migrations-enterprise/

EXPOSE 8080

# Liveness probe endpoint (always 200 if the process runs).
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/api/health || exit 1

USER shadowai

CMD ["shadowai"]
