package middleware

import (
	"REC0NBUBBLE/internal/config"
	"REC0NBUBBLE/internal/handlers"
	"REC0NBUBBLE/internal/services"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func CaptchaRequired(cfg *config.Config, rl *services.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		// Check if IP is blocked
		if blocked, remaining := rl.IsBlocked(ip); blocked {
			c.HTML(http.StatusTooManyRequests, "home.html", gin.H{
				"error": fmt.Sprintf("Too many failed attempts. Please try again in %v minutes.",
					int(remaining.Minutes())+1),
				"Site": cfg,
			})
			c.Abort()
			return
		}

		if c.Request.Method == "GET" {
			handlers.GenerateCaptcha(c)
			c.Next()
			return
		}

		session := sessions.Default(c)

		// Verify session ID first
		expectedSessionID := session.Get("captcha_session_id")
		if expectedSessionID == nil {
			c.HTML(http.StatusBadRequest, "home.html", gin.H{
				"Error": "Captcha session expired. Please try again.",
				"Site":  cfg,
			})
			c.Abort()
			return
		}

		// Get selected numbers from form
		selectedNumbers := c.PostFormArray("captcha_answer[]")
		if len(selectedNumbers) == 0 {
			handlers.IncrementFailedAttempts(session)
			c.HTML(http.StatusBadRequest, "home.html", gin.H{
				"error": "Please select at least one number.",
				"Site":  cfg,
			})
			c.Abort()
			return
		}

		// Calculate sum of selected numbers
		sum := 0
		for _, numStr := range selectedNumbers {
			num, err := strconv.Atoi(numStr)
			if err != nil {
				c.HTML(http.StatusBadRequest, "home.html", gin.H{
					"error": "Invalid selection.",
					"Site":  cfg,
				})
				c.Abort()
				return
			}
			sum += num
		}

		// Verify the sum matches the target
		targetSum := session.Get("captcha_target")
		if targetSum == nil || sum != targetSum.(int) {
			handlers.IncrementFailedAttempts(session)

			// Check if we should block this IP
			if rl.RecordFailure(ip) {
				c.HTML(http.StatusTooManyRequests, "home.html", gin.H{
					"error": fmt.Sprintf("Too many failed attempts. Your IP has been blocked. Please try again later."),
					"Site":  cfg,
				})
				c.Abort()
				return
			}

			handlers.GenerateCaptcha(c)
			c.HTML(http.StatusBadRequest, "home.html", gin.H{
				"error":             "Incorrect selection. Please try again.",
				"Site":              cfg,
				"captchaProblem":    c.MustGet("captcha_problem"),
				"captchaDifficulty": c.MustGet("captcha_difficulty"),
				"captchaOptions":    c.MustGet("captcha_options"),
				"captchaSessionId":  c.MustGet("captcha_session_id"),
			})
			c.Abort()
			return
		}

		// Success - reset rate limiter and clean up session
		rl.Reset(ip)
		handlers.ResetFailedAttempts(session)
		session.Delete("captcha_target")
		session.Delete("captcha_options")
		session.Delete("captcha_session_id")
		session.Save()

		c.Next()
	}
}
