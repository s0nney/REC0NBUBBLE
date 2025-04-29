package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"REC0NBUBBLE/internal/config"
	"REC0NBUBBLE/internal/routes"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set Gin mode based on environment
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// Use the configured cookie secret
	store := cookie.NewStore([]byte(cfg.Security.Session.CookieSecret))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   cfg.Security.Session.MaxAge,
		Secure:   cfg.Security.Session.Secure,
		HttpOnly: cfg.Security.Session.HTTPOnly,
		SameSite: http.SameSiteLaxMode,
	})

	r.Use(sessions.Sessions("session", store))

	// Add config to context
	r.Use(func(c *gin.Context) {
		c.Set("config", cfg)
		c.Next()
	})

	// Setup routes with config
	routes.SetupRoutes(r, cfg)

	// Start server
	addr := fmt.Sprintf(":%d", cfg.App.Port)
	log.Printf("Starting %s server on %s", cfg.App.Name, addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
