package main

import (
	"crypto/tls"
	"net/http"
)

// BUG: InsecureSkipVerify disables cert verification.
func client() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

// BUG: TLS 1.0 minimum.
func oldServer() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10}
}
