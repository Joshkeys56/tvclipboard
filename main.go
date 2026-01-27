package main

import (
	"embed"
	"log"
	"net/http"

	"tvclipboard/pkg/config"
	"tvclipboard/pkg/hub"
	"tvclipboard/pkg/qrcode"
	"tvclipboard/pkg/server"
	"tvclipboard/pkg/token"
)

//go:embed static
var staticFiles embed.FS

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize components
	h := hub.NewHub()
	go h.Run()

	tokenManager := token.NewTokenManager(
		cfg.PrivateKeyHex,
		int(cfg.SessionTimeout.Minutes()),
	)

	qrGen := qrcode.NewGenerator(
		cfg.LocalIP+":"+cfg.Port,
		"http",
		cfg.SessionTimeout,
	)

	srv := server.NewServer(h, tokenManager, qrGen, staticFiles)
	srv.RegisterRoutes()

	// Log startup information
	cfg.LogStartup()

	// Start server
	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		log.Fatal("Server error:", err)
	}
}
