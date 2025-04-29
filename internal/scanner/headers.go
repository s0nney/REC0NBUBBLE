package scanner

import (
	"net/http"

	"REC0NBUBBLE/internal/models"
)

func ScanSecurityHeaders(resp *http.Response) *models.SecurityHeaders {
	return &models.SecurityHeaders{
		HSTS:              resp.Header.Get("Strict-Transport-Security"),
		XFrameOptions:     resp.Header.Get("X-Frame-Options"),
		CSP:               resp.Header.Get("Content-Security-Policy"),
		XContentType:      resp.Header.Get("X-Content-Type-Options"),
		ReferrerPolicy:    resp.Header.Get("Referrer-Policy"),
		PermissionsPolicy: resp.Header.Get("Permissions-Policy"),
		XSSProtection:     resp.Header.Get("X-XSS-Protection"),
		StrictTransport:   resp.Header.Get("Strict-Transport-Policy"),
	}
}
