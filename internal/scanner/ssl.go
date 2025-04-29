package scanner

import (
	"REC0NBUBBLE/internal/models"
	"net/http"
	"time"
)

func ScanSSL(url string) *models.SSLInfo {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.TLS == nil {
		return nil
	}
	defer resp.Body.Close()

	return &models.SSLInfo{
		ValidFrom:   resp.TLS.PeerCertificates[0].NotBefore,
		ValidUntil:  resp.TLS.PeerCertificates[0].NotAfter,
		Issuer:      resp.TLS.PeerCertificates[0].Issuer.CommonName,
		Version:     resp.TLS.Version,
		CipherSuite: resp.TLS.CipherSuite,
	}
}
