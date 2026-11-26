FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
# Keep symbol tables so govulncheck can inspect the release binary.
RUN if [ -n "$VERSION" ]; then \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-X main.version=${VERSION#v}" -o sebastiand ./cmd/sebastiand; \
    else \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o sebastiand ./cmd/sebastiand; \
    fi

FROM alpine:3.21

# Upgrade the base packages at build time, so a release carries the security
# fixes published since the base image tag was cut.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata
COPY --from=builder /build/sebastiand /usr/local/bin/sebastiand
COPY scripts/find-aws-chunked.sh /usr/local/bin/find-aws-chunked

# Run as a non-root user with explicit UID/GID 1000 matching docker-compose.yml.
RUN addgroup -g 1000 sebastian && adduser -D -u 1000 -G sebastian sebastian \
    && mkdir -p /data/files \
    && chown -R sebastian:sebastian /data

# Declare the whole /data tree as a volume, not just /data/files, so the SFTP
# host key at /data/sftp_host_key persists across container restarts instead of
# being regenerated (which would trip host-key-changed warnings on clients).
VOLUME /data

USER sebastian

EXPOSE 9200 9300 9400 9500

ENV SEBASTIAN_ROOT_DIR=/data/files \
    SEBASTIAN_S3_ENABLED=true \
    SEBASTIAN_HTTP_ENABLED=true \
    SEBASTIAN_SFTP_HOST_KEY_PATH=/data/sftp_host_key

ENTRYPOINT ["sebastiand"]
