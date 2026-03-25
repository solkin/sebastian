FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o sebastiand ./cmd/sebastiand

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /build/sebastiand /usr/local/bin/sebastiand

VOLUME /data/files

EXPOSE 9200 9300 9400 9500

ENV SEBASTIAN_ROOT_DIR=/data/files \
    SEBASTIAN_S3_ENABLED=true \
    SEBASTIAN_HTTP_ENABLED=true \
    SEBASTIAN_SFTP_HOST_KEY_PATH=/data/sftp_host_key

ENTRYPOINT ["sebastiand"]
