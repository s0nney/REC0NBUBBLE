package middleware

import (
	"net/http"

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/gin-gonic/gin"
)

func ErrorHandler(c *gin.Context, info ratelimit.Info) {
	c.HTML(http.StatusBadRequest, "results.html", gin.H{
		"error": "Slow down. Try again in 1 minute or so.",
	})
}

func KeyFunc(c *gin.Context) string {
	return c.ClientIP()
}
