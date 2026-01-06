package main

import (
	"crypt-server/internal/app"
	"crypt-server/internal/crypto"
	"crypt-server/internal/store"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	logger := log.New(os.Stdout, "crypt-server ", log.LstdFlags)
	encryptionKey := os.Getenv("FIELD_ENCRYPTION_KEY")
	codec, err := crypto.NewAesGcmCodecFromBase64Key(encryptionKey)
	if err != nil {
		logger.Fatalf("invalid encryption key: %v", err)
	}

	var dataStore store.Store
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		postgresStore, err := store.NewPostgresStore(dbURL, codec)
		if err != nil {
			logger.Fatalf("database connection failed: %v", err)
		}
		dataStore = postgresStore
		logger.Printf("using postgres store")
	} else {
		dataStore = store.NewMemoryStore(codec)
		logger.Printf("using in-memory store")
	}
	renderer := app.NewRenderer("web/templates/layouts/base.html", "web/templates/pages")
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		logger.Fatal("SESSION_KEY is required")
	}
	sessionTTL := 24 * time.Hour
	sessionManager, err := app.NewSessionManager([]byte(sessionKey), "crypt_session", sessionTTL)
	if err != nil {
		logger.Fatalf("invalid session configuration: %v", err)
	}
	settings := app.Settings{
		ApproveOwn:   envBool("APPROVE_OWN", true),
		AllApprove:   envBool("ALL_APPROVE", false),
		SessionTTL:   sessionTTL,
		CookieSecure: envBool("SESSION_COOKIE_SECURE", false),
	}
	csrfManager := app.NewCSRFManager("crypt_csrf", 32)
	server := app.NewServer(dataStore, renderer, logger, sessionManager, csrfManager, settings)

	addr := ":8080"
	logger.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		logger.Fatalf("server stopped: %v", err)
	}
}

func envBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}
