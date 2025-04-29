package handlers

import (
	"REC0NBUBBLE/internal/scanner"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func cleanDomain(domain string) string {
	// URL decode the domain first
	decodedDomain, err := url.QueryUnescape(domain)
	if err != nil {
		return domain
	}

	// Remove common prefixes and clean the domain
	decodedDomain = strings.TrimSpace(decodedDomain)
	decodedDomain = strings.TrimPrefix(decodedDomain, "http://")
	decodedDomain = strings.TrimPrefix(decodedDomain, "https://")
	decodedDomain = strings.TrimPrefix(decodedDomain, "www.")
	decodedDomain = strings.TrimSuffix(decodedDomain, "/")

	// Remove any path or query parameters
	if idx := strings.Index(decodedDomain, "/"); idx != -1 {
		decodedDomain = decodedDomain[:idx]
	}
	if idx := strings.Index(decodedDomain, "?"); idx != -1 {
		decodedDomain = decodedDomain[:idx]
	}

	return decodedDomain
}

// HandleResults displays the scan results
func HandleResults(c *gin.Context) {
	domain := html.EscapeString(c.Param("domain"))

	results, err := scanner.ScanDomain(domain)
	if err != nil {
		c.HTML(http.StatusOK, "results.html", gin.H{
			"domain": domain,
			"error":  err.Error(),
		})
		return
	}

	c.HTML(http.StatusOK, "results.html", gin.H{
		"domain":  domain,
		"results": results,
	})
}
