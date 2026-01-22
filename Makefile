VERSION := $(shell cat VERSION)
LDFLAGS := -ldflags "-X crypt-server/internal/app.Version=$(VERSION)"

.PHONY: build cryptctl clean test run-sqlite

build:
	go build $(LDFLAGS) -o crypt-server ./cmd/crypt-server

cryptctl:
	go build -o cryptctl ./cmd/cryptctl

test:
	go test ./...

clean:
	rm -f crypt-server cryptctl

run-sqlite: build
	@echo "Starting crypt-server with SQLite..."
	@echo "Server will be available at http://localhost:8080"
	SQLITE_PATH=./crypt.db \
	FIELD_ENCRYPTION_KEY=$${FIELD_ENCRYPTION_KEY:-$$(openssl rand -base64 32)} \
	SESSION_KEY=$${SESSION_KEY:-$$(openssl rand -base64 32)} \
	./crypt-server
