package models

import "time"

type ScanResult struct {
	Domain          string
	SSLInfo         *SSLInfo
	SecurityHeaders *SecurityHeaders
	WAFInfo         *WAFInfo
	ServerInfo      *ServerInfo
	Error           error
}

type SSLInfo struct {
	ValidFrom   time.Time
	ValidUntil  time.Time
	Issuer      string
	Version     uint16
	CipherSuite uint16
}

type SecurityHeaders struct {
	HSTS              string
	XFrameOptions     string
	CSP               string
	XContentType      string
	ReferrerPolicy    string
	PermissionsPolicy string
	XSSProtection     string
	StrictTransport   string
}

type WAFInfo struct {
	Detected bool
	Type     string
	Version  string
	Details  string
}

type ServerInfo struct {
	City       string
	Country    string
	Latitude   float64
	Longitude  float64
	ISP        string
	IP         string
	ASN        string
	ServerType string
}

type IPAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
	Server      string  `json:"server"`
}

type ScanResults struct {
	SecurityHeaders *SecurityHeaders
	SSLInfo         *SSLInfo
	WAFInfo         *WAFInfo
	ServerInfo      *ServerInfo
}

type HCaptchaResponse struct {
	Success bool `json:"success"`
}

type VerifyCaptchaRequest struct {
	Response string `json:"h-captcha-response"`
	Domain   string `json:"domain"`
}
