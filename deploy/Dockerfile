# Stage 1: Build binary
FROM golang:1.27-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=1.0.1
ARG BUILD_DATE=""
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X 'github.com/dont-see-big-shark/nas_conn_plus/internal/app.Version=${VERSION}' -X 'github.com/dont-see-big-shark/nas_conn_plus/internal/app.BuildDate=${BUILD_DATE}'" -o nasconnplus ./cmd/nasconnplus

# Stage 2: Ultra-lean Runtime image (< 15MB)
FROM alpine:3.24

# ca-certificates for TLS / Let's Encrypt, tzdata for timezones
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -s /sbin/nologin nasconnplus

COPY --from=builder /build/nasconnplus /usr/local/bin/nasconnplus

VOLUME ["/etc/nasconnplus"]
USER nasconnplus
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD nasconnplus status || exit 1

# In host network mode, nasconnplus scans procfs and binds directly on host ports
ENTRYPOINT ["/usr/local/bin/nasconnplus"]
CMD ["-c", "/etc/nasconnplus/config.json"]
