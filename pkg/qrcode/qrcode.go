package qrcode

import (
	"net/http"
	"strconv"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Generator handles QR code generation
type Generator struct {
	host    string
	scheme  string
	timeout time.Duration
}

// NewGenerator creates a new QR code generator
func NewGenerator(host, scheme string, timeout time.Duration) *Generator {
	return &Generator{
		host:    host,
		scheme:  scheme,
		timeout: timeout,
	}
}

// GenerateQRCodeURL generates a URL for the QR code with an encrypted token
func (g *Generator) GenerateQRCodeURL(encryptedToken string) string {
	return g.scheme + "://" + g.host + "?token=" + encryptedToken + "&mode=client"
}

// ServeQRCode serves a PNG QR code image
func (g *Generator) ServeQRCode(w http.ResponseWriter, r *http.Request, encryptedToken string) {
	url := g.GenerateQRCodeURL(encryptedToken)
	png, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// SessionTimeoutSeconds returns the session timeout in seconds
func (g *Generator) SessionTimeoutSeconds() int {
	return int(g.timeout.Seconds())
}

// Host returns the configured host
func (g *Generator) Host() string {
	return g.host
}

// Scheme returns the configured scheme (http or https)
func (g *Generator) Scheme() string {
	return g.scheme
}

// InjectSessionTimeout injects the session timeout into HTML as a data attribute
func InjectSessionTimeout(html string, timeoutSec int) string {
	tag := `<div class="container" data-session-timeout="` + strconv.Itoa(timeoutSec) + `">`
	oldTag := `<div class="container">`
	return htmlReplace(html, oldTag, tag)
}

// htmlReplace replaces the first occurrence of old with new in html
func htmlReplace(html, old, new string) string {
	if idx := findSubstring(html, old); idx != -1 {
		return html[:idx] + new + html[idx+len(old):]
	}
	return html
}

// findSubstring finds the index of substr in s
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
