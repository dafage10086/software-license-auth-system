package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setCompleteEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("LICENSE_AUTH_ADDR", "127.0.0.1:8787")
	t.Setenv("LICENSE_AUTH_PRODUCT_CODE", "DEMO-PRODUCT")
	t.Setenv("LICENSE_AUTH_KEYGEN_BASE_URL", "http://127.0.0.1:18788")
	t.Setenv("LICENSE_AUTH_KEYGEN_ACCOUNT_ID", "00000000-0000-4000-8000-000000000001")
	t.Setenv("LICENSE_AUTH_KEYGEN_PRODUCT_ID", "00000000-0000-4000-8000-000000000002")
	t.Setenv("LICENSE_AUTH_KEYGEN_PUBLIC_KEY", "TEST_ONLY_PUBLIC_KEY")
}

func TestLoadConfigFromEnvironment(t *testing.T) {
	setCompleteEnvironment(t)

	config, err := loadConfigFromEnvironment()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Addr != "127.0.0.1:8787" || config.ProductCode != "DEMO-PRODUCT" {
		t.Fatalf("unexpected public config: %#v", config)
	}
}

func TestLoadConfigRejectsMissingKeygenConfiguration(t *testing.T) {
	setCompleteEnvironment(t)
	t.Setenv("LICENSE_AUTH_KEYGEN_BASE_URL", "")

	if _, err := loadConfigFromEnvironment(); err == nil {
		t.Fatal("expected missing Keygen configuration to fail")
	}
}

func TestValidateLoopbackAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8787", "[::1]:8787"} {
		if err := validateLoopbackAddress(address); err != nil {
			t.Fatalf("expected loopback address %q to pass: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8787", "192.0.2.1:8787", "invalid"} {
		if err := validateLoopbackAddress(address); err == nil {
			t.Fatalf("expected address %q to fail", address)
		}
	}
}

func TestHTTPHandlerExposesOnlyHealthAndV2Routes(t *testing.T) {
	server := &Server{config: Config{ProductCode: "DEMO-PRODUCT"}}
	handler := newHTTPHandler(server)

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}
	if health.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("security headers are missing")
	}

	legacy := httptest.NewRecorder()
	legacyPath := "/api/" + "v1/trial"
	handler.ServeHTTP(legacy, httptest.NewRequest(http.MethodPost, legacyPath, nil))
	if legacy.Code != http.StatusNotFound {
		t.Fatalf("legacy route status = %d", legacy.Code)
	}
}

func TestAuthorizationHTTPServerUsesBoundedTimeouts(t *testing.T) {
	server := newAuthorizationHTTPServer("127.0.0.1:0", http.NewServeMux())
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 15*time.Second ||
		server.WriteTimeout != 60*time.Second || server.IdleTimeout != 60*time.Second ||
		server.MaxHeaderBytes != 16*1024 {
		t.Fatalf("unexpected HTTP server limits: %#v", server)
	}
}
