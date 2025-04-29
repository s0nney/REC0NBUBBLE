package handlers

import (
	"html"
	"net/http"

	"github.com/gin-gonic/gin"
)

func HandleScan(c *gin.Context) {

	// Get the domain from the form
	domain := cleanDomain(html.EscapeString(c.PostForm("domain")))

	// Validate domain
	if domain == "" {
		c.HTML(http.StatusBadRequest, "home.html", gin.H{
			"error": "Domain is required",
			"title": "REC0NBUBBLE",
		})
		return
	}

	// Captcha validation is now handled by middleware
	// Proceed with the scan
	// TODO: Add your scanning logic here

	// Redirect to results page
	c.Redirect(http.StatusFound, "/results/"+domain)
}

func HandleScanNoCaptcha(c *gin.Context) {
	domain := cleanDomain(c.Query("domain"))

	// Validate domain
	if domain == "" {
		c.HTML(http.StatusBadRequest, "home.html", gin.H{
			"error": "Domain is required",
			"title": "REC0NBUBBLE",
		})
		return
	}

	// Proceed directly to scan
	c.Redirect(http.StatusFound, "/results/"+domain)
}
