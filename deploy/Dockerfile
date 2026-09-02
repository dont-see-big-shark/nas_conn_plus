# Stage 1: Build binary
FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X 'github.com/jadenjoe/nasconnplus/internal/app.Version=1.0.0'" -o nasconnplus ./cmd/nasconnplus

# Stage 2: Ultra-lean Runtime image (< 10MB)
FROM alpine:3.19

# ca-certificates for TLS / Let's Encrypt, tzdata for timezones
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /build/nasconnplus /usr/local/bin/nasconnplus

VOLUME ["/etc/nasconnplus"]

# In host network mode, nasconnplus scans procfs and binds directly on host ports
ENTRYPOINT ["/usr/local/bin/nasconnplus"]
CMD ["-c", "/etc/nasconnplus/config.json"]
