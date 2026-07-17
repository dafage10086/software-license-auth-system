package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	demoProductCode         = "DEMO-PRODUCT"
	productCode             = demoProductCode
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 15 * time.Second
	serverWriteTimeout      = 60 * time.Second
	serverIdleTimeout       = 60 * time.Second
	serverMaxHeaderBytes    = 16 * 1024
)

type Config struct {
	Addr            string
	ProductCode     string
	KeygenBaseURL   string
	KeygenAccountID string
	KeygenProductID string
	KeygenPublicKey string
}

type Server struct {
	v2RateOnce sync.Once
	config     Config
	keygen     KeygenAPI
	v2Rates    *v2RateLimits
}

func main() {
	var addrOverride string
	flag.StringVar(&addrOverride, "addr", "", "loopback listen address")
	flag.Parse()

	config, err := loadConfigFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(addrOverride) != "" {
		config.Addr = strings.TrimSpace(addrOverride)
	}
	if err := validateLoopbackAddress(config.Addr); err != nil {
		log.Fatal(err)
	}

	server := &Server{config: config}
	if err := server.configureKeygen(); err != nil {
		log.Fatal("invalid Keygen configuration")
	}

	log.Printf("Software License Auth gateway started on http://%s", config.Addr)
	log.Fatal(newAuthorizationHTTPServer(config.Addr, newHTTPHandler(server)).ListenAndServe())
}

func loadConfigFromEnvironment() (Config, error) {
	config := Config{
		Addr:            envOrDefault("LICENSE_AUTH_ADDR", "127.0.0.1:8787"),
		ProductCode:     envOrDefault("LICENSE_AUTH_PRODUCT_CODE", demoProductCode),
		KeygenBaseURL:   strings.TrimSpace(os.Getenv("LICENSE_AUTH_KEYGEN_BASE_URL")),
		KeygenAccountID: strings.TrimSpace(os.Getenv("LICENSE_AUTH_KEYGEN_ACCOUNT_ID")),
		KeygenProductID: strings.TrimSpace(os.Getenv("LICENSE_AUTH_KEYGEN_PRODUCT_ID")),
		KeygenPublicKey: strings.TrimSpace(os.Getenv("LICENSE_AUTH_KEYGEN_PUBLIC_KEY")),
	}
	if err := validateLoopbackAddress(config.Addr); err != nil {
		return Config{}, err
	}
	if config.ProductCode == "" || config.KeygenBaseURL == "" ||
		config.KeygenAccountID == "" || config.KeygenProductID == "" ||
		config.KeygenPublicKey == "" {
		return Config{}, errors.New("required license gateway configuration is missing")
	}
	return config, nil
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func validateLoopbackAddress(address string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return errors.New("license gateway address is invalid")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return errors.New("license gateway must listen on a loopback address")
	}
	return nil
}

func (s *Server) expectedProductCode() string {
	if value := strings.TrimSpace(s.config.ProductCode); value != "" {
		return value
	}
	return demoProductCode
}

func (s *Server) configureKeygen() error {
	if !s.keygenConfigured() {
		s.keygen = nil
		return errors.New("Keygen configuration is incomplete")
	}
	client, err := newKeygenClient(
		s.config.KeygenBaseURL,
		s.config.KeygenAccountID,
		s.config.KeygenProductID,
	)
	if err != nil {
		s.keygen = nil
		return err
	}
	s.keygen = client
	return nil
}

func newAuthorizationHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    serverMaxHeaderBytes,
	}
}

func newHTTPHandler(s *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v2/login", s.handleV2Login)
	mux.HandleFunc("/api/v2/activate", s.handleV2Activate)
	mux.HandleFunc("/api/v2/lease", s.handleV2Lease)
	mux.HandleFunc("/api/v2/logout", s.handleV2Logout)
	return withSecurityHeaders(mux)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{"ok":true}`)
}

func nowText() string {
	return time.Now().UTC().Format(time.RFC3339)
}
