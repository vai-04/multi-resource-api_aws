TEST_DATABASE_URL ?= postgres://pokeleague:pokeleague@localhost:5432/pokeleague?sslmode=disable

.PHONY: run up down test test-unit lint fmt vuln build

## up: start Postgres + API in Docker
up:
	docker compose up --build

## down: stop everything and delete the database volume
down:
	docker compose down -v

## run: run the API locally against the compose database
run:
	docker compose up -d db
	DATABASE_URL="$(TEST_DATABASE_URL)" go run ./cmd/api

## test: all tests (unit + integration) with the race detector
test:
	docker compose up -d --wait db
	TEST_DATABASE_URL="$(TEST_DATABASE_URL)" REQUIRE_DB=1 go test -race -count=1 ./...

## test-unit: tests that need no database (integration tests skip themselves)
test-unit:
	go test -race -count=1 ./...

## lint: formatting, vet and staticcheck
lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

## vuln: scan dependencies for known vulnerabilities
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

fmt:
	gofmt -w .

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/api ./cmd/api
