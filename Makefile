VERSION := $(shell cat VERSION)
LDFLAGS := -ldflags "-X crypt-server/internal/app.Version=$(VERSION)"

.PHONY: build clean test

build:
	go build $(LDFLAGS) -o crypt-server ./cmd/crypt-server

test:
	go test ./...

clean:
	rm -f crypt-server
