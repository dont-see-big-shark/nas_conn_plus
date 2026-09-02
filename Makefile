BINARY_NAME := nasconnplus
VERSION ?= 1.0.0
BUILD_DATE := $(shell date -u +'%Y-%m-%d')
LDFLAGS := -s -w -X 'github.com/jadenjoe/nasconnplus/internal/app.Version=$(VERSION)' -X 'github.com/jadenjoe/nasconnplus/internal/app.BuildDate=$(BUILD_DATE)'

.PHONY: all build clean test coverage test-coverage vet lint run docker-build release

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/nasconnplus

test:
	@echo "Running tests..."
	go test -v ./...

coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-coverage:
	@echo "Running tests with coverage and race detector..."
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out
	@echo "Generating HTML coverage report to coverage.html..."
	go tool cover -html=coverage.out -o coverage.html


vet:
	@echo "Running go vet..."
	go vet ./...

lint: vet
	@echo "Code verification passed."

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
