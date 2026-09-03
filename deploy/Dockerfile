# Stage 1: Build binary (fast native build with cross-compilation)
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=1.0.1
ARG BUILD_DATE=""

RUN GOARM="" && \
    if [ "$TARGETARCH" = "arm" ] && [ "$TARGETVARIANT" = "v7" ]; then GOARM="7"; fi && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} GOARM=${GOARM} \
    go build -trimpath -ldflags="-s -w -X 'github.com/dont-see-big-shark/nas_conn_plus/internal/app.Version=${VERSION}' -X 'github.com/dont-see-big-shark/nas_conn_plus/internal/app.BuildDate=${BUILD_DATE}'" \
    -o /nasconnplus ./cmd/nasconnplus

# Stage 2: Ultra-lean Runtime image (< 15MB)
FROM alpine:latest

# ca-certificates for TLS / Let's Encrypt, tzdata for timezones
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -s /sbin/nologin nasconnplus

COPY --from=builder /nasconnplus /usr/local/bin/nasconnplus

VOLUME ["/etc/nasconnplus"]
USER nasconnplus
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/usr/local/bin/nasconnplus", "status"]

# In host network mode, nasconnplus scans procfs and binds directly on host ports
ENTRYPOINT ["/usr/local/bin/nasconnplus"]
CMD ["-c", "/etc/nasconnplus/config.json"]
