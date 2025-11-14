package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
)

const (
	DEFAULT_PORT   = "8080"
	ROOT_CA_CERT   = "root-ca.crt"
	ROOT_CA_KEY    = "root-ca.key"
	COOKIE_LOG     = "cookies.log"
	FORM_DATA_LOG  = "formdata.log"
	CERT_CACHE_DIR = "cert_cache"
)

var (
	// Patterns untuk session cookies - termasuk PHPSESSID
	sessionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(phpsessid|jsessionid|asp\.net_sessionid)`),
		regexp.MustCompile(`(?i)(session|sess|sid|auth|token|csrf|xsrf|jwt)`),
		regexp.MustCompile(`(?i)(cookie|login|remember|auth_token|bearer)`),
		regexp.MustCompile(`(?i)(refresh|access_token|oauth|apikey)`),
	}
)

func isSessionCookie(name string) bool {
	lowerName := strings.ToLower(name)

	// Special check for PHPSESSID (common PHP session cookie)
	if strings.Contains(strings.ToLower(name), "phpsessid") {
		log.Printf("[DEBUG] PHPSESSID detected: %s", name)
		return true
	}

	for _, pattern := range sessionPatterns {
		if pattern.MatchString(lowerName) {
			log.Printf("[DEBUG] Cookie '%s' matched pattern: %s", name, pattern.String())
			return true
		}
	}
	return false
}

func logCookie(method, url, domain, name, value string, secure bool) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	secureFlag := "false"
	if secure {
		secureFlag = "true"
	}

	logEntry := fmt.Sprintf("[%s] %s %s | Domain: %s | %s=%s | Secure: %s",
		timestamp, method, url, domain, name, value, secureFlag)

	log.Println(logEntry)

	// Also log to file
	f, err := os.OpenFile(COOKIE_LOG, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
		return
	}
	defer f.Close()

	_, err = f.WriteString(logEntry + "\n")
	if err != nil {
		log.Printf("Error writing to log file: %v", err)
	}
}

// NEW FUNCTION: Log form data dari POST requests
func logFormData(method, url, domain, contentType string, data []byte) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	log.Printf("📝 FORM DATA CAPTURED:")
	log.Printf("   Method: %s", method)
	log.Printf("   URL: %s", url)
	log.Printf("   Domain: %s", domain)
	log.Printf("   Content-Type: %s", contentType)
	log.Printf("   Data Length: %d bytes", len(data))

	// Format data untuk readability
	dataStr := string(data)
	var formattedData string

	// Check if data looks like URL-encoded form
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		formattedData = fmt.Sprintf("URL-ENCODED:\n%s", dataStr)
	} else if strings.Contains(contentType, "application/json") {
		formattedData = fmt.Sprintf("JSON:\n%s", dataStr)
	} else if strings.Contains(contentType, "multipart/form-data") {
		formattedData = fmt.Sprintf("MULTIPART:\n%s", dataStr)
	} else {
		formattedData = fmt.Sprintf("RAW DATA:\n%s", dataStr)
	}

	// Create log entry
	logEntry := fmt.Sprintf("[%s] FORM DATA | %s %s | Domain: %s | Type: %s | Size: %d bytes\n%s\n",
		timestamp, method, url, domain, contentType, len(data), formattedData)

	log.Printf("📄 FORM DATA:")
	log.Printf("%s", formattedData)

	// Write to formdata.log file
	f, err := os.OpenFile(FORM_DATA_LOG, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening formdata log file: %v", err)
		return
	}
	defer f.Close()

	_, err = f.WriteString(logEntry + "\n" + strings.Repeat("-", 80) + "\n")
	if err != nil {
		log.Printf("Error writing to formdata log file: %v", err)
	}
}

// NEW FUNCTION: Extract dan log form data dari request
func extractAndLogFormData(req *http.Request, domain string) bool {
	// Only process POST, PUT, PATCH methods dengan body
	if !strings.Contains(strings.ToUpper(req.Method), "POST") &&
		!strings.Contains(strings.ToUpper(req.Method), "PUT") &&
		!strings.Contains(strings.ToUpper(req.Method), "PATCH") {
		return false
	}

	// Skip if no content-type atau empty content
	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		return false
	}

	// Read body data
	var bodyData []byte

	// For requests dengan body
	if req.Body != nil {
		bodyData, _ = io.ReadAll(req.Body)

		// Restore body untuk proxy
		req.Body = io.NopCloser(bytes.NewReader(bodyData))
	}

	// Log only if there's data (> 0 bytes)
	if len(bodyData) > 0 {
		logFormData(req.Method, req.URL.String(), domain, contentType, bodyData)
		return true
	}

	return false
}

// SAFER FIX: Load Root CA dengan robust error handling dan null checks
func setupCustomRootCA() {
	log.Println("🔧 Setting up custom Root CA...")

	// Check if root CA files exist
	if _, err := os.Stat(ROOT_CA_CERT); os.IsNotExist(err) {
		log.Fatalf("❌ Root CA certificate not found: %s", ROOT_CA_CERT)
	}
	if _, err := os.Stat(ROOT_CA_KEY); os.IsNotExist(err) {
		log.Fatalf("❌ Root CA private key not found: %s", ROOT_CA_KEY)
	}

	// Load Root CA certificate dan key
	rootCAcert, err := os.ReadFile(ROOT_CA_CERT)
	if err != nil {
		log.Fatalf("❌ Failed to read Root CA certificate: %v", err)
	}

	rootCAkey, err := os.ReadFile(ROOT_CA_KEY)
	if err != nil {
		log.Fatalf("❌ Failed to read Root CA private key: %v", err)
	}

	log.Printf("📜 Loaded Root CA certificate: %d bytes", len(rootCAcert))
	log.Printf("🔑 Loaded Root CA private key: %d bytes", len(rootCAkey))

	// CRITICAL: Set goproxy global variables
	goproxy.CA_CERT = rootCAcert
	goproxy.CA_KEY = rootCAkey

	log.Printf("✅ Set goproxy.CA_CERT and goproxy.CA_KEY")

	// CRITICAL FIX: Manually parse X509KeyPair untuk update GoproxyCa
	// goproxy.GoproxyCa might not auto-update, so we explicitly parse it
	goproxy.GoproxyCa, err = tls.X509KeyPair(goproxy.CA_CERT, goproxy.CA_KEY)
	if err != nil {
		log.Fatalf("❌ Failed to parse custom Root CA: %v", err)
	}

	log.Printf("✅ Custom Root CA parsed and assigned to goproxy.GoproxyCa")

	// SAFER: Check if certificate is properly loaded without accessing .Leaf
	if len(goproxy.GoproxyCa.Certificate) > 0 {
		log.Printf("🔍 Certificate loaded successfully with %d certificate(s) in chain", len(goproxy.GoproxyCa.Certificate))
	} else {
		log.Printf("⚠️ Warning: Certificate chain is empty")
	}

	// Create certificate cache directory
	err = os.MkdirAll(CERT_CACHE_DIR, 0755)
	if err != nil {
		log.Fatalf("❌ Failed to create certificate cache directory: %v", err)
	}

	// List existing certificates for debugging
	files, err := os.ReadDir(CERT_CACHE_DIR)
	if err == nil {
		log.Printf("📁 Certificate cache directory: %s", CERT_CACHE_DIR)
		log.Printf("📋 Existing certificates: %d", len(files))
	} else {
		log.Printf("📁 Certificate cache directory: %s (empty or access denied)", CERT_CACHE_DIR)
	}

	log.Println("✅ Custom Root CA setup completed successfully")
}

func main() {
	// CRITICAL: Setup custom Root CA FIRST before creating proxy
	setupCustomRootCA()

	// Create proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true // Enable verbose logging

	// Get port from environment or use default
	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = DEFAULT_PORT
	}

	// Parse port as integer to validate
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("Invalid port number: %v", err)
	}

	// Use built-in MITM dengan updated GoproxyCa
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Request handler for cookie AND form data capture
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Printf("[DEBUG] Request: %s %s", req.Method, req.URL.String())

		// Capture cookies from request
		if len(req.Cookies()) > 0 {
			log.Printf("[DEBUG] Found %d cookies in request", len(req.Cookies()))
			for _, cookie := range req.Cookies() {
				log.Printf("[DEBUG] Cookie: %s = %s", cookie.Name, cookie.Value)
				if isSessionCookie(cookie.Name) {
					log.Printf("[SUCCESS] Session cookie matched: %s", cookie.Name)
					logCookie(req.Method, req.URL.String(), req.URL.Host, cookie.Name, cookie.Value, cookie.Secure)
				}
			}
		}

		// NEW: Capture form data from POST/PUT/PATCH requests
		if extractAndLogFormData(req, req.URL.Host) {
			log.Printf("[SUCCESS] Form data captured from %s request", req.Method)
		}

		return req, nil
	})

	// Response handler for cookie capture
	proxy.OnResponse().DoFunc(func(res *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		log.Printf("[DEBUG] Response: %s", res.Status)

		// Capture cookies from response (Set-Cookie headers)
		if res != nil && len(res.Cookies()) > 0 {
			log.Printf("[DEBUG] Found %d cookies in response", len(res.Cookies()))
			for _, cookie := range res.Cookies() {
				log.Printf("[DEBUG] Response cookie: %s = %s", cookie.Name, cookie.Value)
				if isSessionCookie(cookie.Name) {
					log.Printf("[SUCCESS] Response session cookie matched: %s", cookie.Name)
					logCookie("SET-COOKIE", ctx.Req.URL.String(), ctx.Req.URL.Host, cookie.Name, cookie.Value, cookie.Secure)
				}
			}
		}

		return res
	})

	// Start the proxy server
	log.Printf("🚀 Session Cookie Sniffer Proxy starting on port %s", port)
	log.Printf("📝 Cookies will be logged to: %s", COOKIE_LOG)
	log.Printf("📋 Form data will be logged to: %s", FORM_DATA_LOG)
	log.Printf("🔐 Using custom Root CA: %s", ROOT_CA_CERT)
	log.Printf("📁 Certificate cache: %s", CERT_CACHE_DIR)
	log.Printf("📍 Configure your browser to use this proxy: localhost:%s", port)
	log.Printf("✅ HTTPS MITM with custom Root CA is enabled")
	log.Printf("✅ POST/PUT/PATCH form data logging is enabled")
	log.Printf("")
	log.Printf("🔧 SAFER FIX APPLIED:")
	log.Printf("   - Custom Root CA loaded via goproxy.CA_CERT dan goproxy.CA_KEY")
	log.Printf("   - EXPLICITLY parsed X509KeyPair untuk update goproxy.GoproxyCa")
	log.Printf("   - Using goproxy.AlwaysMitm")
	log.Printf("   - Safe certificate validation without .Leaf access")
	log.Printf("   - Robust error handling with null checks")
	log.Printf("   - POST/PUT/PATCH form data capture implemented")
	log.Printf("")
	log.Printf("Press Ctrl+C to stop the proxy\n")

	// Start server
	err := http.ListenAndServe(":"+port, proxy)
	if err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}
