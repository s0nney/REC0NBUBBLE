package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"REC0NBUBBLE/internal/models"
)

type ScanJob struct {
	Name     string
	Scanner  func(*http.Response, string) interface{}
	Response *http.Response
	Domain   string
}

func ScanDomain(domain string) (*models.ScanResults, error) {
	// Clean and prepare the domain
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	// First try HTTPS
	fullURL := "https://" + domain
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(fullURL)
	if err != nil {
		// If HTTPS fails, try HTTP
		fullURL = "http://" + domain
		resp, err = client.Get(fullURL)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to domain: %v", err)
		}
	}
	defer resp.Body.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create scan jobs
	jobs := []ScanJob{
		{
			Name: "security_headers",
			Scanner: func(r *http.Response, _ string) interface{} {
				return ScanSecurityHeaders(r)
			},
			Response: resp,
			Domain:   domain,
		},
		{
			Name: "ssl",
			Scanner: func(_ *http.Response, d string) interface{} {
				return ScanSSL(fullURL)
			},
			Response: resp,
			Domain:   domain,
		},
		{
			Name: "waf",
			Scanner: func(r *http.Response, _ string) interface{} {
				return ScanWAF(r.Header)
			},
			Response: resp,
			Domain:   domain,
		},
		{
			Name: "server_info",
			Scanner: func(_ *http.Response, d string) interface{} {
				return ScanServerInfo(d)
			},
			Response: resp,
			Domain:   domain,
		},
	}

	// Create results channels
	results := make(chan struct {
		name   string
		result interface{}
	}, len(jobs))

	// Create error channel
	errChan := make(chan error, len(jobs))

	// Create WaitGroup for job tracking
	var wg sync.WaitGroup

	// Launch scan jobs
	for _, job := range jobs {
		wg.Add(1)
		go func(j ScanJob) {
			defer wg.Done()

			// Create job timeout context
			jobCtx, jobCancel := context.WithTimeout(ctx, 10*time.Second)
			defer jobCancel()

			// Create result channel
			done := make(chan interface{}, 1)

			// Run scan in goroutine
			go func() {
				result := j.Scanner(j.Response, j.Domain)
				done <- result
			}()

			// Wait for completion or timeout
			select {
			case result := <-done:
				results <- struct {
					name   string
					result interface{}
				}{j.Name, result}
			case <-jobCtx.Done():
				errChan <- fmt.Errorf("%s scan timed out", j.Name)
			}
		}(job)
	}

	// Close channels when all jobs complete
	go func() {
		wg.Wait()
		close(results)
		close(errChan)
	}()

	// Collect results
	scanResults := &models.ScanResults{}
	for result := range results {
		switch result.name {
		case "security_headers":
			scanResults.SecurityHeaders = result.result.(*models.SecurityHeaders)
		case "ssl":
			scanResults.SSLInfo = result.result.(*models.SSLInfo)
		case "waf":
			scanResults.WAFInfo = result.result.(*models.WAFInfo)
		case "server_info":
			scanResults.ServerInfo = result.result.(*models.ServerInfo)
		}
	}

	// Check for errors
	var errs []string
	for err := range errChan {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return scanResults, fmt.Errorf("scan errors: %s", strings.Join(errs, "; "))
	}

	return scanResults, nil
}

// Helper function to get WAF type from header name
func GetWAFTypeFromHeader(header string) string {
	wafTypes := map[string]string{
		"X-AWS-EC2-Metadata-Token-TTL-Seconds": "AWS WAF",
		"X-BIG-IP":                             "F5 BIG-IP",
		"X-Sucuri-ID":                          "Sucuri WAF",
		"X-Sucuri-Cache":                       "Sucuri CloudProxy WAF",
		"X-Fortinet-WAF":                       "Fortinet FortiWeb WAF",
		"X-Iinfo":                              "Imperva SecureSphere WAF",
		"X-Sqreen":                             "Sqreen",
		"X-Reblaze":                            "Reblaze WAF",
		"X-Safe3":                              "Safe3 WAF",
		"X-Naxsi":                              "NAXSI WAF",
		"X-DataPower-Auth":                     "IBM WebSphere DataPower",
		"X-Qrator-Protection":                  "QRATOR WAF",
		"X-DDoS-Guard":                         "DDoS-Guard WAF",
		"X-YXLink-WAF":                         "Yundun WAF",
		"X-WangZhanBao":                        "WangZhanBao WAF",
		"X-Webcoment":                          "Webcoment Firewall",
		"X-Akamai-Transform":                   "Akamai WAF",
		"Server":                               "Barracuda WAF",
	}

	if wafType, exists := wafTypes[header]; exists {
		return wafType
	}
	return "Unknown WAF"
}
