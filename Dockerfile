# syntax=docker/dockerfile:1.7
# OpenCTEM Tenable.sc connector: one static binary on distroless, non-root.
#
# The image holds the connector only: no shell, no package manager, no
# scanner. It needs no capability, no privileged syscall and no listening
# port, so it runs under the default seccomp profile with
# --cap-drop ALL --read-only and a writable volume for its state.
#
# Base images are pinned by digest (tag kept for readability). Refresh with
#   docker buildx imagetools inspect <image>:<tag>

FROM --platform=$BUILDPLATFORM ghcr.io/openctemio/mirror/golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-w -s -X main.Version=${VERSION}" -o /out/connector-tenable . \
    && mkdir -p /out/data/state /out/data/outbox /out/etc/connectors

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
LABEL org.opencontainers.image.title="OpenCTEM Tenable.sc connector" \
      org.opencontainers.image.description="Connects a Tenable Security Center to OpenCTEM; the Tenable.sc API keys stay in this container" \
      org.opencontainers.image.source="https://github.com/openctemio/connector-tenable" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder /out/connector-tenable /usr/local/bin/connector-tenable
# State (identity, renewed key) and outbox, owned by the non-root user
# (65532); mount a volume at /var/lib/openctem to keep them.
COPY --from=builder --chown=65532:65532 /out/data /var/lib/openctem
ENV SENSOR_STATE_DIR=/var/lib/openctem/state \
    SENSOR_OUTBOX_DIR=/var/lib/openctem/outbox
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/connector-tenable"]
