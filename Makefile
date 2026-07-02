.PHONY: run test build docker-up

run:
	go run ./cmd/clph-web

test:
	go test ./...

build:
	go build ./...

docker-up:
	docker compose up --build
