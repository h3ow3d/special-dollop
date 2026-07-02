GO_BIN := $(shell command -v go 2>/dev/null)
DOCKER_BIN := $(shell command -v docker 2>/dev/null)
GO_IMAGE ?= golang:1.25.7

.PHONY: run test build docker-up

run:
ifdef GO_BIN
	$(GO_BIN) run ./cmd/clph-web
else ifdef DOCKER_BIN
	$(DOCKER_BIN) compose up --build
else
	@echo "Neither 'go' nor 'docker' is installed. Install Go 1.25+ or Docker to use 'make run'." >&2
	@exit 1
endif

test:
ifdef GO_BIN
	$(GO_BIN) test ./...
else ifdef DOCKER_BIN
	$(DOCKER_BIN) run --rm -v "$(CURDIR):/src" -w /src $(GO_IMAGE) go test ./...
else
	@echo "Neither 'go' nor 'docker' is installed. Install Go 1.25+ or Docker to use 'make test'." >&2
	@exit 1
endif

build:
ifdef GO_BIN
	$(GO_BIN) build ./...
else ifdef DOCKER_BIN
	$(DOCKER_BIN) run --rm -v "$(CURDIR):/src" -w /src $(GO_IMAGE) go build -buildvcs=false ./...
else
	@echo "Neither 'go' nor 'docker' is installed. Install Go 1.25+ or Docker to use 'make build'." >&2
	@exit 1
endif

docker-up:
ifdef DOCKER_BIN
	$(DOCKER_BIN) compose up --build
else
	@echo "'docker' is not installed. Install Docker to use 'make docker-up'." >&2
	@exit 1
endif
