# syntax=docker/dockerfile:1
# AuditTrail Go services: api, worker, witness, migrate, purge, admin, verify.
# One image; each compose service picks its binary with `entrypoint`.
#   docker build -f deploy/docker/go.Dockerfile -t audittrail/server .
# Base images are pinned by digest (THREAT_MODEL T13); Dependabot bumps them.

FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
# Cross-compile natively on the build host (no QEMU for multi-arch images).
ARG TARGETOS=linux TARGETARCH=amd64
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath GOOS=$TARGETOS GOARCH=$TARGETARCH
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY packages/ingestion-go ./packages/ingestion-go
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; mkdir -p /out /state; \
    for c in api worker witness migrate purge admin verify healthcheck; do \
      go build -ldflags="-s -w -X main.version=${VERSION}" -o "/out/audittrail-$c" "./packages/ingestion-go/cmd/$c"; \
    done

# distroless: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ /usr/local/bin/
# Writable state for the witness (seed + state file); named volumes mounted
# here inherit nonroot ownership.
COPY --from=build --chown=nonroot:nonroot /state /var/lib/audittrail
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/audittrail-api"]
