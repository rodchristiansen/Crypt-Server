package main

import (
	"crypt-server/internal/app"
	"crypt-server/internal/store"
	"log"
	"net/http"
	"os"
)

func main() {
	logger := log.New(os.Stdout, "crypt-server ", log.LstdFlags)
	var dataStore store.Store
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		postgresStore, err := store.NewPostgresStore(dbURL)
		if err != nil {
			logger.Fatalf("database connection failed: %v", err)
		}
		dataStore = postgresStore
		logger.Printf("using postgres store")
	} else {
		dataStore = store.NewMemoryStore()
		logger.Printf("using in-memory store")
	}
	renderer := app.NewRenderer("web/templates/layouts/base.html", "web/templates/pages")
	server := app.NewServer(dataStore, renderer, logger)

	addr := ":8080"
	logger.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		logger.Fatalf("server stopped: %v", err)
	}
}
