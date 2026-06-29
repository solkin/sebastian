FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o sebastiand ./cmd/sebastiand

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /build/sebastiand /usr/local/bin/sebastiand

# Run as a non-root user that owns the data directory.
RUN addgroup -S sebastian && adduser -S -G sebastian sebastian \
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
