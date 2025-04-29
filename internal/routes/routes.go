package routes

import (
	"html/template"
	"time"

	"REC0NBUBBLE/internal/config"
	"REC0NBUBBLE/internal/handlers"
	"REC0NBUBBLE/internal/middleware"
	"REC0NBUBBLE/internal/services"

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/gin-gonic/gin"
)

// SetupRoutes configures all the routes for the application
func SetupRoutes(r *gin.Engine, cfg *config.Config) {
	// Create captcha rate limiter
	rl := services.NewRateLimiter(
		cfg.Security.RateLimit.CaptchaFails,
		time.Duration(cfg.Security.RateLimit.BlockDuration)*time.Minute,
	)

	store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  time.Minute * time.Duration(cfg.Security.RateLimit.PerMinute),
		Limit: uint(cfg.Security.RateLimit.Requests),
	})
	mw := ratelimit.RateLimiter(store, &ratelimit.Options{
		ErrorHandler: middleware.ErrorHandler,
		KeyFunc:      middleware.KeyFunc,
	})
	// Load HTML templates
	r.SetFuncMap(template.FuncMap{})
	r.LoadHTMLGlob(cfg.Templates.Directory + "/*")

	// Serve static files
	r.Static("/static", cfg.Static.Directory)

	// Routes
	r.GET("/", handlers.HandleHome)

	// Conditionally apply captcha based on config
	if cfg.Security.Captcha.Enabled {
		r.POST("/scan", mw, middleware.CaptchaRequired(cfg, rl), handlers.HandleScan)
		r.GET("/scan", mw, handlers.HandleHome)
	} else {
		r.POST("/scan", mw, handlers.HandleScanNoCaptcha)
		r.GET("/scan", mw, handlers.HandleScanNoCaptcha)
	}

	r.GET("/results/:domain", mw, handlers.HandleResults)
}
