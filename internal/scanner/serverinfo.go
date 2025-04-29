package scanner

import (
	"REC0NBUBBLE/internal/models"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func ScanServerInfo(domain string) *models.ServerInfo {
	serverInfo := &models.ServerInfo{
		City:       "Unknown",
		Country:    "Unknown",
		Latitude:   0,
		Longitude:  0,
		ISP:        "Unknown",
		IP:         "Unknown",
		ASN:        "Unknown",
		ServerType: "Unknown",
	}

	// Resolve IP address
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return serverInfo
	}

	// Get the first IPv4 address
	var ipAddr string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipAddr = ipv4.String()
			break
		}
	}

	if ipAddr == "" {
		return serverInfo
	}

	// Store the IP address
	serverInfo.IP = ipAddr

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Make request to ip-api.com
	resp, err := client.Get("http://ip-api.com/json/" + ipAddr)
	if err != nil {
		return serverInfo
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return serverInfo
	}

	var ipInfo models.IPAPIResponse
	if err := json.Unmarshal(body, &ipInfo); err != nil {
		return serverInfo
	}

	// Update server info with API response
	if ipInfo.Status == "success" {
		serverInfo.City = ipInfo.City
		serverInfo.Country = ipInfo.Country
		serverInfo.Latitude = ipInfo.Lat
		serverInfo.Longitude = ipInfo.Lon
		serverInfo.ISP = ipInfo.ISP
		// Extract just the AS number
		if idx := strings.Index(ipInfo.AS, " "); idx != -1 {
			serverInfo.ASN = ipInfo.AS[:idx]
		} else {
			serverInfo.ASN = ipInfo.AS
		}
	}

	// Try to get server type from HTTP response
	if serverResp, err := client.Get("https://" + domain); err == nil {
		defer serverResp.Body.Close()
		serverInfo.ServerType = serverResp.Header.Get("Server")
	}

	return serverInfo
}
