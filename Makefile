BINARY_NAME := nasconnplus
VERSION ?= 1.0.0
BUILD_DATE := $(shell date -u +'%Y-%m-%d')
LDFLAGS := -s -w -X 'github.com/jadenjoe/nasconnplus/internal/app.Version=$(VERSION)' -X 'github.com/jadenjoe/nasconnplus/internal/app.BuildDate=$(BUILD_DATE)'

.PHONY: all build clean test run docker-build release

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/nasconnplus

test:
	@echo "Running tests..."
	go test -v ./...

vet:
	@echo "Running go vet..."
	go vet ./...

clean:
	@echo "Cleaning binaries..."
	rm -f $(BINARY_NAME)
	rm -rf dist/

# Cross compilation for common NAS architectures
release: clean
	@echo "Building release binaries for Linux amd64, arm64, armv7..."
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/nasconnplus
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/nasconnplus
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-armv7 ./cmd/nasconnplus
	@echo "Release binaries created in dist/"

docker-build:
	docker build -t $(BINARY_NAME):latest -f deploy/Dockerfile .
