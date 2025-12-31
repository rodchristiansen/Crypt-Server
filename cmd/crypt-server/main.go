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
	dataStore := store.NewStore()
	renderer := app.NewRenderer("web/templates/layouts/base.html", "web/templates/pages")
	server := app.NewServer(dataStore, renderer, logger)

	addr := ":8080"
	logger.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		logger.Fatalf("server stopped: %v", err)
	}
}
