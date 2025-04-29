package scanner

import (
	"net/http"
	"strings"

	"REC0NBUBBLE/internal/models"
)

func ScanWAF(headers http.Header) *models.WAFInfo {
	wafInfo := &models.WAFInfo{
		Detected: false,
		Type:     "None detected",
		Version:  "",
		Details:  "",
	}

	// Version detection patterns
	versionPatterns := map[string]func(http.Header) (string, string){
		"Cloudflare": func(h http.Header) (string, string) {
			// Cloudflare version info might be in Server header
			server := h.Get("Server")
			if strings.Contains(strings.ToLower(server), "cloudflare") {
				parts := strings.Split(server, "/")
				if len(parts) > 1 {
					return parts[1], "Server: " + server
				}
			}
			return "", ""
		},
		"F5 BIG-IP": func(h http.Header) (string, string) {
			// BIG-IP version might be encoded in headers
			server := h.Get("Server")
			if strings.Contains(strings.ToLower(server), "big-ip") {
				return strings.TrimPrefix(server, "BIG-IP "), "Server: " + server
			}
			return "", ""
		},
		"Imperva": func(h http.Header) (string, string) {
			// Imperva sometimes includes version in X-Iinfo
			if xIinfo := h.Get("X-Iinfo"); xIinfo != "" {
				return "Details available", "X-Iinfo: " + xIinfo
			}
			return "", ""
		},
		"Sucuri": func(h http.Header) (string, string) {
			// Sucuri version might be in Server header
			server := h.Get("Server")
			if strings.Contains(strings.ToLower(server), "sucuri") {
				parts := strings.Split(server, "/")
				if len(parts) > 1 {
					return parts[1], "Server: " + server
				}
			}
			return "", ""
		},
		"Akamai": func(h http.Header) (string, string) {
			// Akamai version info might be in X-Akamai-Transform
			if transform := h.Get("X-Akamai-Transform"); transform != "" {
				return "Details available", "X-Akamai-Transform: " + transform
			}
			return "", ""
		},
	}

	// Common WAF signatures with their corresponding patterns
	wafSignatures := map[string]map[string][]string{
		"Cloudflare": {
			"CF-RAY":          {"*"},
			"CF-Cache-Status": {"*"},
			"Server":          {"cloudflare"},
		},
		"AWS WAF": {
			"X-AMZ-CF-ID":                          {"*"},
			"X-AWS-EC2-Metadata-Token-TTL-Seconds": {"*"},
			"Server":                               {"awselb/", "aws"},
		},
		"Akamai": {
			"X-Akamai-Transform":     {"*"},
			"X-Akamai-SSL-Client":    {"*"},
			"Server":                 {"akamai"},
			"X-Cache":                {"Akamai"},
			"X-True-Cache-Key":       {"*"},
			"X-Akamai-Transformed":   {"*"},
			"X-Akamai-Configuration": {"*"},
		},
		"Sucuri": {
			"X-Sucuri-ID":       {"*"},
			"X-Sucuri-Cache":    {"*"},
			"X-Sucuri-ClientIP": {"*"},
			"Server":            {"Sucuri/", "sucuri"},
		},
		"F5 BIG-IP": {
			"X-BIG-IP":      {"*"},
			"Server":        {"bigip", "f5"},
			"X-F5":          {"*"},
			"X-F5-Auth":     {"*"},
			"X-F5-Port":     {"*"},
			"X-F5-Response": {"*"},
		},
		"Imperva": {
			"X-Iinfo":       {"*"},
			"Server":        {"imperva"},
			"X-Imperva-WAF": {"*"},
			"X-CDN":         {"Imperva"},
		},
		"Barracuda": {
			"Server":          {"barracuda", "bwaf"},
			"X-Barracuda":     {"*"},
			"X-Barracuda-WAF": {"*"},
		},
		"Fortinet": {
			"X-Fortinet-WAF": {"*"},
			"Server":         {"fortinet", "fortigate"},
			"X-FortiGate":    {"*"},
		},
		"NAXSI": {
			"X-Naxsi":        {"*"},
			"Server":         {"naxsi"},
			"X-Naxsi-Action": {"*"},
		},
		"Citrix NetScaler": {
			"Via":         {"ns-cache", "netscaler"},
			"Client-IP":   {"*"},
			"X-Client-IP": {"*"},
			"X-Citrix":    {"*"},
		},
		"DDoS-Guard": {
			"Server":            {"ddos-guard"},
			"X-DDoS-Guard":      {"*"},
			"X-DDoS-Protection": {"*"},
		},
		"Reblaze": {
			"X-Reblaze":            {"*"},
			"Server":               {"reblaze"},
			"X-Reblaze-Protection": {"*"},
		},
		"Sqreen": {
			"X-Sqreen":       {"*"},
			"X-Protected-By": {"sqreen"},
		},
		"Webcoment": {
			"X-Webcoment": {"*"},
			"Server":      {"webcoment"},
		},
		"Yundun": {
			"X-YXLink-WAF": {"*"},
			"Server":       {"yundun"},
			"X-Yundun":     {"*"},
		},
		"WangZhanBao": {
			"X-WangZhanBao": {"*"},
			"Server":        {"wangzhanbao"},
		},
	}

	// Check for WAF presence
	for wafName, signatures := range wafSignatures {
		for header, patterns := range signatures {
			if headerValue := headers.Get(header); headerValue != "" {
				headerValueLower := strings.ToLower(headerValue)

				// Check if any pattern matches
				for _, pattern := range patterns {
					if pattern == "*" || strings.Contains(headerValueLower, strings.ToLower(pattern)) {
						wafInfo.Detected = true
						wafInfo.Type = wafName
						return wafInfo
					}
				}
			}
		}
	}

	// Check for generic security headers that might indicate WAF presence
	securityHeaders := []string{
		"X-Security",
		"X-WAF",
		"X-Firewall",
		"X-Security-Proxy",
		"X-Application-Context",
		"X-Protected-By",
	}

	for _, header := range securityHeaders {
		if headers.Get(header) != "" {
			wafInfo.Detected = true
			wafInfo.Type = "Generic WAF/Security Solution"
			return wafInfo
		}
	}

	// When a WAF is detected, try to get version info
	if wafInfo.Detected {
		if versionDetector, exists := versionPatterns[wafInfo.Type]; exists {
			version, details := versionDetector(headers)
			if version != "" {
				wafInfo.Version = version
				wafInfo.Details = details
			}
		}
	}

	return wafInfo
}
