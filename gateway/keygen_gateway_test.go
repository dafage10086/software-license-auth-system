package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeKeygenAPI struct {
	loginFn          func(context.Context, string, string) (KeygenSession, error)
	currentUserFn    func(context.Context, string) (KeygenUser, error)
	resolveLicenseFn func(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error)
	ensureMachineFn  func(context.Context, string, KeygenLicense, DeviceBinding) (KeygenMachine, error)
	getMachineFn     func(context.Context, string, string) (KeygenMachine, error)
	getLicenseFn     func(context.Context, string, string) (KeygenLicense, error)
	heartbeatFn      func(context.Context, string, string) error
	checkoutFn       func(context.Context, string, string, int) (KeygenMachineFile, error)
	revokeTokenFn    func(context.Context, string) error
}

func (f *fakeKeygenAPI) Login(ctx context.Context, email, password string) (KeygenSession, error) {
	if f.loginFn == nil {
		return KeygenSession{}, errors.New("unexpected Login call")
	}
	return f.loginFn(ctx, email, password)
}

func (f *fakeKeygenAPI) CurrentUser(ctx context.Context, token string) (KeygenUser, error) {
	if f.currentUserFn == nil {
		return KeygenUser{}, errors.New("unexpected CurrentUser call")
	}
	return f.currentUserFn(ctx, token)
}

func (f *fakeKeygenAPI) ResolveLicense(ctx context.Context, token, productID, cardKey string, binding DeviceBinding) (KeygenLicenseResolution, error) {
	if f.resolveLicenseFn == nil {
		return KeygenLicenseResolution{}, errors.New("unexpected ResolveLicense call")
	}
	return f.resolveLicenseFn(ctx, token, productID, cardKey, binding)
}

func (f *fakeKeygenAPI) EnsureMachine(ctx context.Context, token string, license KeygenLicense, binding DeviceBinding) (KeygenMachine, error) {
	if f.ensureMachineFn == nil {
		return KeygenMachine{}, errors.New("unexpected EnsureMachine call")
	}
	return f.ensureMachineFn(ctx, token, license, binding)
}

func (f *fakeKeygenAPI) GetMachine(ctx context.Context, token, machineID string) (KeygenMachine, error) {
	if f.getMachineFn == nil {
		return KeygenMachine{}, errors.New("unexpected GetMachine call")
	}
	return f.getMachineFn(ctx, token, machineID)
}

func (f *fakeKeygenAPI) GetLicense(ctx context.Context, token, licenseID string) (KeygenLicense, error) {
	if f.getLicenseFn == nil {
		return KeygenLicense{}, errors.New("unexpected GetLicense call")
	}
	return f.getLicenseFn(ctx, token, licenseID)
}

func (f *fakeKeygenAPI) Heartbeat(ctx context.Context, token, machineID string) error {
	if f.heartbeatFn == nil {
		return errors.New("unexpected Heartbeat call")
	}
	return f.heartbeatFn(ctx, token, machineID)
}

func (f *fakeKeygenAPI) Checkout(ctx context.Context, token, machineID string, ttl int) (KeygenMachineFile, error) {
	if f.checkoutFn == nil {
		return KeygenMachineFile{}, errors.New("unexpected Checkout call")
	}
	return f.checkoutFn(ctx, token, machineID, ttl)
}

func (f *fakeKeygenAPI) RevokeToken(ctx context.Context, token string) error {
	if f.revokeTokenFn == nil {
		return errors.New("unexpected RevokeToken call")
	}
	return f.revokeTokenFn(ctx, token)
}

func newConfiguredV2TestServer(t *testing.T, api KeygenAPI) *Server {
	t.Helper()
	s := newTestServer(t)
	s.config.KeygenBaseURL = "http://127.0.0.1:18788"
	s.config.KeygenAccountID = "account-1"
	s.config.KeygenProductID = "product-1"
	s.config.KeygenPublicKey = strings.Repeat("A", 64)
	s.keygen = api
	return s
}

func validV2Components() map[string]string {
	return map[string]string{
		"smbios":      strings.Repeat("A", 64),
		"bios":        strings.Repeat("B", 64),
		"system_disk": strings.Repeat("C", 64),
	}
}

func fivePhysicalComponents() map[string]string {
	return map[string]string{
		"smbios":       strings.Repeat("A", 64),
		"baseboard":    strings.Repeat("B", 64),
		"bios":         strings.Repeat("C", 64),
		"system_disk":  strings.Repeat("D", 64),
		"machine_guid": strings.Repeat("E", 64),
		"device_key":   strings.Repeat("F", 64),
	}
}

func cloneComponents(components map[string]string) map[string]string {
	cloned := make(map[string]string, len(components))
	for name, fingerprint := range components {
		cloned[name] = fingerprint
	}
	return cloned
}

func TestValidDeviceBindingRequiresThreePhysicalComponents(t *testing.T) {
	fingerprint := strings.Repeat("F", 64)
	twoPhysicalAndDeviceKey := map[string]string{
		"bios":       strings.Repeat("A", 64),
		"smbios":     strings.Repeat("B", 64),
		"device_key": strings.Repeat("C", 64),
	}
	if validDeviceBinding(fingerprint, twoPhysicalAndDeviceKey) {
		t.Fatal("validDeviceBinding counted device_key as a physical component")
	}

	threePhysical := validV2Components()
	if !validDeviceBinding(fingerprint, threePhysical) {
		t.Fatal("validDeviceBinding rejected three valid physical components")
	}
	if !validPhysicalComponents(threePhysical) {
		t.Fatal("validPhysicalComponents rejected three valid physical components")
	}
	withDeviceKey := cloneComponents(threePhysical)
	withDeviceKey["device_key"] = strings.Repeat("D", 64)
	if !validDeviceBinding(fingerprint, withDeviceKey) {
		t.Fatal("validDeviceBinding rejected an optional device_key")
	}
	if !validPhysicalComponents(withDeviceKey) {
		t.Fatal("validPhysicalComponents rejected an optional device_key")
	}
}

func TestValidPhysicalComponentsRejectsMalformedOrIncompleteBindings(t *testing.T) {
	for _, tc := range []struct {
		name       string
		components map[string]string
	}{
		{name: "missing third physical", components: map[string]string{"bios": strings.Repeat("A", 64), "smbios": strings.Repeat("B", 64)}},
		{name: "unknown name", components: map[string]string{"bios": strings.Repeat("A", 64), "smbios": strings.Repeat("B", 64), "system_disk": strings.Repeat("C", 64), "cpu": strings.Repeat("D", 64)}},
		{name: "lowercase hash", components: map[string]string{"bios": strings.Repeat("a", 64), "smbios": strings.Repeat("B", 64), "system_disk": strings.Repeat("C", 64)}},
		{name: "non sha hash", components: map[string]string{"bios": "SERIAL-123", "smbios": strings.Repeat("B", 64), "system_disk": strings.Repeat("C", 64)}},
		{name: "duplicate physical fingerprint", components: map[string]string{"bios": strings.Repeat("A", 64), "smbios": strings.Repeat("A", 64), "system_disk": strings.Repeat("C", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validPhysicalComponents(tc.components) {
				t.Fatal("validPhysicalComponents accepted an invalid physical binding")
			}
			if validDeviceBinding(strings.Repeat("F", 64), tc.components) {
				t.Fatal("validDeviceBinding accepted an invalid physical binding")
			}
		})
	}

	for _, fingerprint := range []string{strings.Repeat("f", 64), "SERIAL-123"} {
		if validDeviceBinding(fingerprint, validV2Components()) {
			t.Fatalf("validDeviceBinding accepted invalid combined fingerprint %q", fingerprint)
		}
	}
}

func TestMatchesPhysicalMajorityUsesBoundMachineQuorum(t *testing.T) {
	bound := fivePhysicalComponents()
	oneChanged := cloneComponents(bound)
	oneChanged["bios"] = strings.Repeat("1", 64)
	if !matchesPhysicalMajority(bound, oneChanged) {
		t.Fatal("one changed physical component out of five did not meet majority")
	}

	threeChanged := cloneComponents(bound)
	threeChanged["bios"] = strings.Repeat("1", 64)
	threeChanged["system_disk"] = strings.Repeat("2", 64)
	threeChanged["machine_guid"] = strings.Repeat("3", 64)
	if matchesPhysicalMajority(bound, threeChanged) {
		t.Fatal("two matches out of five incorrectly met majority")
	}
}

func TestMatchesPhysicalMajorityIgnoresDeviceKeyAndRejectsTooFewPhysical(t *testing.T) {
	bound := fivePhysicalComponents()
	deviceKeyChanged := cloneComponents(bound)
	deviceKeyChanged["device_key"] = strings.Repeat("9", 64)
	if !matchesPhysicalMajority(bound, deviceKeyChanged) {
		t.Fatal("device_key change affected physical majority")
	}

	twoPhysical := map[string]string{
		"bios":       strings.Repeat("A", 64),
		"smbios":     strings.Repeat("B", 64),
		"device_key": strings.Repeat("F", 64),
	}
	if matchesPhysicalMajority(twoPhysical, bound) {
		t.Fatal("majority accepted a bound machine with fewer than three physical components")
	}
	if matchesPhysicalMajority(bound, twoPhysical) {
		t.Fatal("majority accepted a candidate with fewer than three physical components")
	}
}

func TestV2RoutesFailClosedWithoutKeygenConfig(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"secret"}`))
	rr := httptest.NewRecorder()

	s.handleV2Login(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestV2RoutesAreRegisteredWhenKeygenIsDisabled(t *testing.T) {
	s := newTestServer(t)
	h := newHTTPHandler(s)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"secret"}`))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestAccountEmailNormalizesUsername(t *testing.T) {
	got, err := accountEmail("  User.Name_01  ")
	if err != nil {
		t.Fatalf("accountEmail returned error: %v", err)
	}
	if got != "user.name_01@accounts.license.invalid" {
		t.Fatalf("email = %q", got)
	}
}

func TestAccountEmailRejectsInvalidUsernames(t *testing.T) {
	for _, username := range []string{
		"abc",
		strings.Repeat("a", 33),
		"user@example.com",
		"user name",
		"用户1234",
	} {
		t.Run(username, func(t *testing.T) {
			if _, err := accountEmail(username); err == nil {
				t.Fatalf("accountEmail(%q) succeeded", username)
			}
		})
	}
}

func TestDecodeV2JSONRejectsUnknownAndTrailingData(t *testing.T) {
	for _, body := range []string{
		`{"product":"DEMO-PRODUCT","username":"user1","password":"secret","ttl":7200}`,
		`{"product":"DEMO-PRODUCT","username":"user1","password":"secret"}{}`,
		`{"product":`,
	} {
		t.Run(body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(body))
			rr := httptest.NewRecorder()
			var dst V2LoginRequest
			if err := decodeV2JSON(rr, req, &dst); err == nil {
				t.Fatalf("decodeV2JSON accepted %q", body)
			}
		})
	}
}

func TestDecodeV2JSONRejectsBodyOver32KiB(t *testing.T) {
	body := `{"product":"DEMO-PRODUCT","username":"user1","password":"` + strings.Repeat("x", 33*1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	var dst V2LoginRequest

	if err := decodeV2JSON(rr, req, &dst); err == nil {
		t.Fatal("decodeV2JSON accepted body over 32 KiB")
	}
}

func TestV2LoginNormalizesUsernameAndReturnsSession(t *testing.T) {
	api := &fakeKeygenAPI{
		loginFn: func(_ context.Context, email, password string) (KeygenSession, error) {
			if email != "user.name@accounts.license.invalid" || password != "test-password" {
				t.Fatalf("unexpected credentials: email=%q password_match=%v", email, password == "test-password")
			}
			return KeygenSession{Token: "session-token", TokenID: "token-id", UserID: "user-id"}, nil
		},
		currentUserFn: func(_ context.Context, token string) (KeygenUser, error) {
			if token != "session-token" {
				t.Fatalf("unexpected current-user token")
			}
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":" User.Name ","password":"test-password","client_version":"2.0.0"}`))
	rr := httptest.NewRecorder()

	s.handleV2Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response V2LoginResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || response.SessionToken != "session-token" || response.UserID != "user-id" || response.Username != "user.name" || response.ServerTime == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if strings.Contains(rr.Body.String(), "test-password") || strings.Contains(rr.Body.String(), "token-id") {
		t.Fatalf("response leaked sensitive/internal data: %s", rr.Body.String())
	}
}

func TestV2LoginMapsInvalidCredentialsToGenericUnauthorized(t *testing.T) {
	api := &fakeKeygenAPI{
		loginFn: func(context.Context, string, string) (KeygenSession, error) {
			return KeygenSession{}, &KeygenUpstreamError{StatusCode: http.StatusUnauthorized}
		},
	}
	s := newConfiguredV2TestServer(t, api)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"wrong-password"}`))
	rr := httptest.NewRecorder()

	s.handleV2Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "wrong-password") || strings.Contains(rr.Body.String(), "Keygen") {
		t.Fatalf("response leaked details: %s", rr.Body.String())
	}
}

func TestV2LoginRejectsInactiveUserAndRevokesIssuedSession(t *testing.T) {
	for _, status := range []string{"BANNED", "DISABLED"} {
		t.Run(status, func(t *testing.T) {
			revoked := false
			api := &fakeKeygenAPI{
				loginFn: func(context.Context, string, string) (KeygenSession, error) {
					return KeygenSession{Token: "issued-session-token", TokenID: "token-id", UserID: "user-id"}, nil
				},
				currentUserFn: func(context.Context, string) (KeygenUser, error) {
					return KeygenUser{ID: "user-id", Status: status}, nil
				},
				revokeTokenFn: func(_ context.Context, token string) error {
					if token != "issued-session-token" {
						t.Fatalf("unexpected revoke token")
					}
					revoked = true
					return nil
				},
			}
			s := newConfiguredV2TestServer(t, api)
			req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"test-password"}`))
			rr := httptest.NewRecorder()

			s.handleV2Login(rr, req)

			if rr.Code != http.StatusForbidden || !revoked {
				t.Fatalf("status=%d revoked=%v body=%s", rr.Code, revoked, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "issued-session-token") {
				t.Fatalf("response exposed revoked session: %s", rr.Body.String())
			}
		})
	}
}

func TestV2LoginRevokesMalformedIssuedSession(t *testing.T) {
	revoked := false
	api := &fakeKeygenAPI{
		loginFn: func(context.Context, string, string) (KeygenSession, error) {
			return KeygenSession{Token: "orphan-session-token", TokenID: "token-id"}, nil
		},
		revokeTokenFn: func(_ context.Context, token string) error {
			if token != "orphan-session-token" {
				t.Fatalf("unexpected revoke token")
			}
			revoked = true
			return nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"test-password"}`))
	rr := httptest.NewRecorder()

	s.handleV2Login(rr, req)

	if rr.Code != http.StatusServiceUnavailable || !revoked {
		t.Fatalf("status=%d revoked=%v body=%s", rr.Code, revoked, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "orphan-session-token") {
		t.Fatalf("response exposed malformed session: %s", rr.Body.String())
	}
}

func TestV2LoginRejectsInvalidRequestsBeforeCallingKeygen(t *testing.T) {
	called := false
	api := &fakeKeygenAPI{
		loginFn: func(context.Context, string, string) (KeygenSession, error) {
			called = true
			return KeygenSession{}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	for _, tc := range []struct {
		name   string
		method string
		body   string
		status int
	}{
		{name: "method", method: http.MethodGet, body: `{}`, status: http.StatusMethodNotAllowed},
		{name: "unknown field", method: http.MethodPost, body: `{"product":"DEMO-PRODUCT","username":"user1","password":"secret","path":"/tokens"}`, status: http.StatusBadRequest},
		{name: "product", method: http.MethodPost, body: `{"product":"OTHER","username":"user1","password":"secret"}`, status: http.StatusBadRequest},
		{name: "username", method: http.MethodPost, body: `{"product":"DEMO-PRODUCT","username":"bad user","password":"secret"}`, status: http.StatusBadRequest},
		{name: "password", method: http.MethodPost, body: `{"product":"DEMO-PRODUCT","username":"user1","password":""}`, status: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v2/login", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			s.handleV2Login(rr, req)
			if rr.Code != tc.status {
				t.Fatalf("status = %d, want %d body=%s", rr.Code, tc.status, rr.Body.String())
			}
		})
	}
	if called {
		t.Fatal("Keygen was called for an invalid request")
	}
}

func TestV2ActivateResolvesOwnedCardAndEnsuresMachine(t *testing.T) {
	expires := time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second)
	fingerprint := strings.Repeat("D", 64)
	api := &fakeKeygenAPI{
		currentUserFn: func(_ context.Context, token string) (KeygenUser, error) {
			if token != "user-token" {
				t.Fatalf("unexpected current-user token")
			}
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		resolveLicenseFn: func(_ context.Context, token, productID, cardKey string, binding DeviceBinding) (KeygenLicenseResolution, error) {
			if token != "user-token" || productID != "product-1" || cardKey != "YEAR-KEY-123" || binding.Fingerprint != fingerprint {
				t.Fatalf("unexpected resolve arguments: token_match=%v product=%q card=%q", token == "user-token", productID, cardKey)
			}
			return KeygenLicenseResolution{License: KeygenLicense{
				ID:        "license-1",
				Key:       "YEAR-KEY-123",
				Status:    "ACTIVE",
				Plan:      "YEAR",
				Price:     128,
				OwnerID:   "user-id",
				ProductID: "product-1",
			}}, nil
		},
		ensureMachineFn: func(_ context.Context, token string, license KeygenLicense, binding DeviceBinding) (KeygenMachine, error) {
			if token != "user-token" || license.ID != "license-1" || binding.Fingerprint != fingerprint || !reflect.DeepEqual(binding.Components, validV2Components()) {
				t.Fatalf("unexpected ensure arguments: token_match=%v license=%#v binding=%#v", token == "user-token", license, binding)
			}
			return KeygenMachine{ID: "machine-1", Fingerprint: fingerprint, LicenseID: "license-1", OwnerID: "user-id", Components: binding.Components}, nil
		},
		getLicenseFn: func(_ context.Context, token, licenseID string) (KeygenLicense, error) {
			if token != "user-token" || licenseID != "license-1" {
				t.Fatalf("unexpected refreshed license request")
			}
			return KeygenLicense{ID: "license-1", Key: "YEAR-KEY-123", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: expires, OwnerID: "user-id", ProductID: "product-1"}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, err := json.Marshal(V2ActivateRequest{
		Product:           productCode,
		CardKey:           " year-key-123 ",
		DeviceFingerprint: fingerprint,
		Components:        validV2Components(),
		ClientVersion:     "2.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Activate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response V2ActivateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || response.UserID != "user-id" || response.LicenseID != "license-1" || response.MachineID != "machine-1" || response.MachineFingerprint != fingerprint || response.Plan != "YEAR" || response.Price != 128 || response.ExpiresAt != expires.Format(time.RFC3339) {
		t.Fatalf("unexpected response: %#v", response)
	}
	if strings.Contains(rr.Body.String(), "user-token") || strings.Contains(rr.Body.String(), "YEAR-KEY-123") {
		t.Fatalf("response leaked credential/card: %s", rr.Body.String())
	}
}

func TestV2ActivateTrialUsesNoCardKey(t *testing.T) {
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		resolveLicenseFn: func(_ context.Context, _, _, cardKey string, _ DeviceBinding) (KeygenLicenseResolution, error) {
			if cardKey != "" {
				t.Fatalf("trial card key = %q", cardKey)
			}
			return KeygenLicenseResolution{License: KeygenLicense{ID: "trial-license", Key: "TRIAL-INTERNAL", Status: "ACTIVE", Plan: "TRIAL", Price: 0, OwnerID: "user-id", ProductID: "product-1"}}, nil
		},
		ensureMachineFn: func(_ context.Context, _ string, _ KeygenLicense, binding DeviceBinding) (KeygenMachine, error) {
			return KeygenMachine{ID: "machine-1", Fingerprint: binding.Fingerprint, LicenseID: "trial-license", OwnerID: "user-id", Components: binding.Components}, nil
		},
		getLicenseFn: func(context.Context, string, string) (KeygenLicense, error) {
			return KeygenLicense{ID: "trial-license", Key: "TRIAL-INTERNAL", Status: "ACTIVE", Plan: "TRIAL", Price: 0, ExpiresAt: expires, OwnerID: "user-id", ProductID: "product-1"}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2ActivateRequest{Product: productCode, DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components()})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Activate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestV2ActivateRetriesNewMachineUntilFirstActivationExpiryAppears(t *testing.T) {
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	getLicenseCalls := 0
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		resolveLicenseFn: func(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error) {
			return KeygenLicenseResolution{License: KeygenLicense{ID: "trial-license", Key: "TRIAL-INTERNAL", Status: "ACTIVE", Plan: "TRIAL", Price: 0, OwnerID: "user-id", ProductID: "product-1"}}, nil
		},
		ensureMachineFn: func(_ context.Context, _ string, _ KeygenLicense, binding DeviceBinding) (KeygenMachine, error) {
			return KeygenMachine{ID: "machine-1", Fingerprint: binding.Fingerprint, LicenseID: "trial-license", OwnerID: "user-id", Components: binding.Components}, nil
		},
		getLicenseFn: func(context.Context, string, string) (KeygenLicense, error) {
			getLicenseCalls++
			license := KeygenLicense{ID: "trial-license", Key: "TRIAL-INTERNAL", Status: "ACTIVE", Plan: "TRIAL", Price: 0, OwnerID: "user-id", ProductID: "product-1"}
			if getLicenseCalls > 1 {
				license.ExpiresAt = expires
			}
			return license, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2ActivateRequest{Product: productCode, DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components()})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Activate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if getLicenseCalls != 2 {
		t.Fatalf("GetLicense calls = %d", getLicenseCalls)
	}
}

func TestV2ActivateNoCardReusesBoundPaidMachine(t *testing.T) {
	expires := time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second)
	boundFingerprint := strings.Repeat("A", 64)
	candidateFingerprint := strings.Repeat("F", 64)
	boundComponents := fivePhysicalComponents()
	candidateComponents := cloneComponents(boundComponents)
	candidateComponents["bios"] = strings.Repeat("9", 64)
	license := KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: expires, BusinessExpiresAt: expires, OwnerID: "user-id", ProductID: "product-1"}
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		resolveLicenseFn: func(_ context.Context, _, _, cardKey string, binding DeviceBinding) (KeygenLicenseResolution, error) {
			if cardKey != "" || binding.Fingerprint != candidateFingerprint || !reflect.DeepEqual(binding.Components, candidateComponents) {
				t.Fatalf("unexpected resolution request: card=%q binding=%#v", cardKey, binding)
			}
			return KeygenLicenseResolution{
				License: license,
				Machine: &KeygenMachine{ID: "machine-1", Fingerprint: boundFingerprint, LicenseID: "license-1", OwnerID: "user-id", Components: boundComponents},
			}, nil
		},
		getLicenseFn: func(context.Context, string, string) (KeygenLicense, error) {
			return license, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2ActivateRequest{Product: productCode, DeviceFingerprint: candidateFingerprint, Components: candidateComponents})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Activate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response V2ActivateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Plan != "YEAR" || response.MachineID != "machine-1" || response.MachineFingerprint != boundFingerprint {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestV2ActivateNoCardRejectsUnboundPaidLicense(t *testing.T) {
	machineCalled := false
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		resolveLicenseFn: func(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error) {
			return KeygenLicenseResolution{License: KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, OwnerID: "user-id", ProductID: "product-1"}}, nil
		},
		ensureMachineFn: func(context.Context, string, KeygenLicense, DeviceBinding) (KeygenMachine, error) {
			machineCalled = true
			return KeygenMachine{}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2ActivateRequest{Product: productCode, DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components()})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Activate(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if machineCalled {
		t.Fatal("unbound paid license created a machine without a card key")
	}
}

func TestV2ActivateMapsAmbiguousAndDeviceMismatchToConflict(t *testing.T) {
	for _, upstreamErr := range []error{ErrKeygenAmbiguous, ErrKeygenDeviceMismatch} {
		api := &fakeKeygenAPI{
			currentUserFn: func(context.Context, string) (KeygenUser, error) {
				return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
			},
			resolveLicenseFn: func(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error) {
				return KeygenLicenseResolution{}, upstreamErr
			},
		}
		s := newConfiguredV2TestServer(t, api)
		body, _ := json.Marshal(V2ActivateRequest{Product: productCode, DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components()})
		req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer user-token")
		rr := httptest.NewRecorder()

		s.handleV2Activate(rr, req)

		if rr.Code != http.StatusConflict {
			t.Fatalf("error=%v status=%d body=%s", upstreamErr, rr.Code, rr.Body.String())
		}
	}
}

func TestV2ActivateRejectsInvalidHardwareBeforeCallingKeygen(t *testing.T) {
	called := false
	api := &fakeKeygenAPI{
		resolveLicenseFn: func(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error) {
			called = true
			return KeygenLicenseResolution{}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	validFingerprint := strings.Repeat("D", 64)
	for _, tc := range []struct {
		name        string
		fingerprint string
		components  map[string]string
	}{
		{name: "raw fingerprint", fingerprint: "SERIAL-123", components: validV2Components()},
		{name: "too few", fingerprint: validFingerprint, components: map[string]string{"bios": strings.Repeat("A", 64), "smbios": strings.Repeat("B", 64)}},
		{name: "unknown component", fingerprint: validFingerprint, components: map[string]string{"bios": strings.Repeat("A", 64), "smbios": strings.Repeat("B", 64), "cpu": strings.Repeat("C", 64)}},
		{name: "raw serial", fingerprint: validFingerprint, components: map[string]string{"bios": "SERIAL-123", "smbios": strings.Repeat("B", 64), "system_disk": strings.Repeat("C", 64)}},
		{name: "lowercase hash", fingerprint: validFingerprint, components: map[string]string{"bios": strings.Repeat("a", 64), "smbios": strings.Repeat("B", 64), "system_disk": strings.Repeat("C", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(V2ActivateRequest{Product: productCode, DeviceFingerprint: tc.fingerprint, Components: tc.components})
			req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer user-token")
			rr := httptest.NewRecorder()
			s.handleV2Activate(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
	if called {
		t.Fatal("Keygen was called for invalid hardware")
	}
}

func TestV2ActivateRejectsUnavailableOrExpiredLicense(t *testing.T) {
	for _, tc := range []struct {
		name    string
		license KeygenLicense
		status  int
	}{
		{name: "revoked", license: KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "SUSPENDED", Plan: "YEAR", Price: 128, ExpiresAt: time.Now().UTC().Add(time.Hour), OwnerID: "user-id", ProductID: "product-1"}, status: http.StatusForbidden},
		{name: "expired", license: KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: time.Now().UTC().Add(-time.Hour), OwnerID: "user-id", ProductID: "product-1"}, status: http.StatusForbidden},
		{name: "wrong price", license: KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), OwnerID: "user-id", ProductID: "product-1"}, status: http.StatusForbidden},
		{name: "wrong product", license: KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: time.Now().UTC().Add(time.Hour), OwnerID: "user-id", ProductID: "other-product"}, status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			machineCalled := false
			api := &fakeKeygenAPI{
				currentUserFn: func(context.Context, string) (KeygenUser, error) {
					return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
				},
				resolveLicenseFn: func(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error) {
					return KeygenLicenseResolution{License: tc.license}, nil
				},
				ensureMachineFn: func(context.Context, string, KeygenLicense, DeviceBinding) (KeygenMachine, error) {
					machineCalled = true
					return KeygenMachine{}, nil
				},
			}
			s := newConfiguredV2TestServer(t, api)
			body, _ := json.Marshal(V2ActivateRequest{Product: productCode, CardKey: "YEAR-KEY", DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components()})
			req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer user-token")
			rr := httptest.NewRecorder()
			s.handleV2Activate(rr, req)
			if rr.Code != tc.status {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
			if machineCalled {
				t.Fatal("machine was ensured for invalid license")
			}
		})
	}
}

func TestV2ActivateRejectsCardOwnedByAnotherUser(t *testing.T) {
	machineCalled := false
	expires := time.Now().UTC().Add(time.Hour)
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "current-user", Status: "ACTIVE"}, nil
		},
		resolveLicenseFn: func(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error) {
			return KeygenLicenseResolution{License: KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: expires, BusinessExpiresAt: expires, OwnerID: "other-user", ProductID: "product-1"}}, nil
		},
		ensureMachineFn: func(context.Context, string, KeygenLicense, DeviceBinding) (KeygenMachine, error) {
			machineCalled = true
			return KeygenMachine{}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2ActivateRequest{Product: productCode, CardKey: "YEAR-KEY", DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components()})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Activate(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if machineCalled {
		t.Fatal("machine was ensured for another user's card")
	}
}

func TestV2LeaseAlwaysChecksOutForExactlyOneHour(t *testing.T) {
	now := time.Now().UTC()
	businessExpiresAt := now.Add(24 * time.Hour)
	heartbeatCalled := false
	challenge := strings.Repeat("f", 43)
	manifestSHA256 := strings.Repeat("E", 64)
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		getMachineFn: func(_ context.Context, _ string, machineID string) (KeygenMachine, error) {
			return KeygenMachine{ID: machineID, Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id", Components: validV2Components()}, nil
		},
		getLicenseFn: func(context.Context, string, string) (KeygenLicense, error) {
			return KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: businessExpiresAt, BusinessExpiresAt: businessExpiresAt, OwnerID: "user-id", ProductID: "product-1"}, nil
		},
		heartbeatFn: func(_ context.Context, token, machineID string) error {
			if token != "user-token" || machineID != "machine-1" {
				t.Fatal("unexpected heartbeat arguments")
			}
			heartbeatCalled = true
			return nil
		},
		checkoutFn: func(_ context.Context, token, machineID string, ttl int) (KeygenMachineFile, error) {
			if !heartbeatCalled {
				t.Fatal("checkout occurred before heartbeat")
			}
			if token != "user-token" || machineID != "machine-1" || ttl != keygenCheckoutTTLSeconds {
				t.Fatalf("unexpected checkout: token_match=%v machine=%q ttl=%d", token == "user-token", machineID, ttl)
			}
			return KeygenMachineFile{
				Certificate: "signed-machine-file",
				Algorithm:   "base64+ed25519",
				TTL:         keygenCheckoutTTLSeconds,
				IssuedAt:    now,
				ExpiresAt:   now.Add(time.Hour),
			}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2LeaseRequest{
		Product:           productCode,
		MachineID:         "machine-1",
		DeviceFingerprint: strings.Repeat("F", 64),
		Components:        validV2Components(),
		ManifestSHA256:    manifestSHA256,
		Challenge:         challenge,
		ClientVersion:     "2.0.0",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/lease", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Lease(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response V2LeaseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || response.MachineFile != "signed-machine-file" || response.MachineFileExpiresAt != now.Add(time.Hour).Format(time.RFC3339) || response.RefreshAfterSeconds != 600 || response.Plan != "YEAR" || response.BusinessExpiresAt != businessExpiresAt.Format(time.RFC3339) {
		t.Fatalf("unexpected response: %#v", response)
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response fields: %v", err)
	}
	bindingInput := "LICENSE-AUTH-LEASE-V1\x00signed-machine-file\x00" + manifestSHA256 + "\x00" + challenge
	bindingDigest := sha256.Sum256([]byte(bindingInput))
	wantBinding := fmt.Sprintf("%X", bindingDigest[:])
	if payload["challenge"] != challenge || payload["manifest_sha256"] != manifestSHA256 || payload["binding_sha256"] != wantBinding {
		t.Fatalf("lease proof fields are not bound: %#v", payload)
	}
	if strings.Contains(rr.Body.String(), "user-token") {
		t.Fatalf("response leaked token: %s", rr.Body.String())
	}
}

func TestV2LeaseRejectsPhysicalMinorityBeforeHeartbeatOrCheckout(t *testing.T) {
	bound := fivePhysicalComponents()
	candidate := cloneComponents(bound)
	candidate["smbios"] = strings.Repeat("1", 64)
	candidate["baseboard"] = strings.Repeat("2", 64)
	candidate["bios"] = strings.Repeat("3", 64)
	heartbeatCalled := false
	checkoutCalled := false
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		getMachineFn: func(context.Context, string, string) (KeygenMachine, error) {
			return KeygenMachine{ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id", Components: bound}, nil
		},
		heartbeatFn: func(context.Context, string, string) error {
			heartbeatCalled = true
			return nil
		},
		checkoutFn: func(context.Context, string, string, int) (KeygenMachineFile, error) {
			checkoutCalled = true
			return KeygenMachineFile{}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2LeaseRequest{
		Product:           productCode,
		MachineID:         "machine-1",
		DeviceFingerprint: strings.Repeat("F", 64),
		Components:        candidate,
		ManifestSHA256:    strings.Repeat("E", 64),
		Challenge:         strings.Repeat("z", 43),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v2/lease", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Lease(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if heartbeatCalled || checkoutCalled {
		t.Fatalf("mismatched binding reached heartbeat=%v checkout=%v", heartbeatCalled, checkoutCalled)
	}
}

func TestV2LeaseChallengeCanOnlyBeUsedOnce(t *testing.T) {
	now := time.Now().UTC()
	checkoutCalls := 0
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
		getMachineFn: func(context.Context, string, string) (KeygenMachine, error) {
			return KeygenMachine{ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id", Components: validV2Components()}, nil
		},
		getLicenseFn: func(context.Context, string, string) (KeygenLicense, error) {
			return KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: now.Add(time.Hour), BusinessExpiresAt: now.Add(time.Hour), OwnerID: "user-id", ProductID: "product-1"}, nil
		},
		heartbeatFn: func(context.Context, string, string) error { return nil },
		checkoutFn: func(context.Context, string, string, int) (KeygenMachineFile, error) {
			checkoutCalls++
			return KeygenMachineFile{Certificate: "signed-machine-file", Algorithm: "base64+ed25519", TTL: keygenCheckoutTTLSeconds, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body, _ := json.Marshal(V2LeaseRequest{
		Product:           productCode,
		MachineID:         "machine-1",
		DeviceFingerprint: strings.Repeat("D", 64),
		Components:        validV2Components(),
		ManifestSHA256:    strings.Repeat("E", 64),
		Challenge:         strings.Repeat("g", 43),
	})

	statuses := make([]int, 0, 2)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v2/lease", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer user-token")
		rr := httptest.NewRecorder()
		s.handleV2Lease(rr, req)
		statuses = append(statuses, rr.Code)
	}
	if !reflect.DeepEqual(statuses, []int{http.StatusOK, http.StatusConflict}) {
		t.Fatalf("statuses = %v, want [%d %d]", statuses, http.StatusOK, http.StatusConflict)
	}
	if checkoutCalls != 1 {
		t.Fatalf("checkout calls = %d, want 1", checkoutCalls)
	}
}

func TestV2LeaseSeparatelyRateLimitsHeartbeatAndCheckout(t *testing.T) {
	now := time.Now().UTC()
	for _, operation := range []string{"heartbeat", "checkout"} {
		t.Run(operation, func(t *testing.T) {
			heartbeatCalls := 0
			checkoutCalls := 0
			api := &fakeKeygenAPI{
				currentUserFn: func(context.Context, string) (KeygenUser, error) {
					return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
				},
				getMachineFn: func(context.Context, string, string) (KeygenMachine, error) {
					return KeygenMachine{ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id", Components: validV2Components()}, nil
				},
				getLicenseFn: func(context.Context, string, string) (KeygenLicense, error) {
					return KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: now.Add(time.Hour), BusinessExpiresAt: now.Add(time.Hour), OwnerID: "user-id", ProductID: "product-1"}, nil
				},
				heartbeatFn: func(context.Context, string, string) error {
					heartbeatCalls++
					return nil
				},
				checkoutFn: func(context.Context, string, string, int) (KeygenMachineFile, error) {
					checkoutCalls++
					return KeygenMachineFile{Certificate: "signed-machine-file", Algorithm: "base64+ed25519", TTL: keygenCheckoutTTLSeconds, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, nil
				},
			}
			s := newConfiguredV2TestServer(t, api)
			s.v2RateLimits().authenticatedAction.entries[actionRateKey("user-token", operation)] = rateWindowEntry{
				started: now,
				count:   v2ActionLimit,
			}
			body, _ := json.Marshal(V2LeaseRequest{
				Product:           productCode,
				MachineID:         "machine-1",
				DeviceFingerprint: strings.Repeat("D", 64),
				Components:        validV2Components(),
				ManifestSHA256:    strings.Repeat("E", 64),
				Challenge:         strings.Repeat("h", 43),
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v2/lease", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer user-token")
			rr := httptest.NewRecorder()

			s.handleV2Lease(rr, req)

			if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "600" {
				t.Fatalf("status=%d retry-after=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
			}
			wantHeartbeatCalls := 0
			if heartbeatCalls != wantHeartbeatCalls || checkoutCalls != 0 {
				t.Fatalf("heartbeat calls=%d want=%d checkout calls=%d", heartbeatCalls, wantHeartbeatCalls, checkoutCalls)
			}
		})
	}
}

func TestV2LeaseRejectsUnknownTTLAndInvalidProofFieldsBeforeCheckout(t *testing.T) {
	called := false
	api := &fakeKeygenAPI{
		checkoutFn: func(context.Context, string, string, int) (KeygenMachineFile, error) {
			called = true
			return KeygenMachineFile{}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	valid := V2LeaseRequest{Product: productCode, MachineID: "machine-1", DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components(), ManifestSHA256: strings.Repeat("E", 64), Challenge: strings.Repeat("f", 43)}
	validJSON, _ := json.Marshal(valid)
	componentsJSON, _ := json.Marshal(validV2Components())
	missingComponentsJSON := strings.Replace(string(validJSON), `,"components":`+string(componentsJSON), "", 1)
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "unknown ttl", body: strings.TrimSuffix(string(validJSON), "}") + `,"ttl":7200}`},
		{name: "machine path", body: strings.Replace(string(validJSON), `"machine-1"`, `"../tokens"`, 1)},
		{name: "raw fingerprint", body: strings.Replace(string(validJSON), strings.Repeat("D", 64), "SERIAL-123", 1)},
		{name: "missing components", body: missingComponentsJSON},
		{name: "raw manifest", body: strings.Replace(string(validJSON), strings.Repeat("E", 64), "manifest.json", 1)},
		{name: "short challenge", body: strings.Replace(string(validJSON), strings.Repeat("f", 43), "short", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v2/lease", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer user-token")
			rr := httptest.NewRecorder()
			s.handleV2Lease(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
	if called {
		t.Fatal("checkout was called for invalid lease request")
	}
}

func TestV2LeaseRejectsOverlongOrInvalidUpstreamLease(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		file KeygenMachineFile
	}{
		{name: "overlong", file: KeygenMachineFile{Certificate: "file", Algorithm: "base64+ed25519", TTL: 3600, IssuedAt: now, ExpiresAt: now.Add(3701 * time.Second)}},
		{name: "expired", file: KeygenMachineFile{Certificate: "file", Algorithm: "base64+ed25519", TTL: 3600, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}},
		{name: "wrong ttl", file: KeygenMachineFile{Certificate: "file", Algorithm: "base64+ed25519", TTL: 7200, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}},
		{name: "wrong algorithm", file: KeygenMachineFile{Certificate: "file", Algorithm: "base64+rsa-sha256", TTL: 3600, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeKeygenAPI{
				currentUserFn: func(context.Context, string) (KeygenUser, error) {
					return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
				},
				getMachineFn: func(context.Context, string, string) (KeygenMachine, error) {
					return KeygenMachine{ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id", Components: validV2Components()}, nil
				},
				getLicenseFn: func(context.Context, string, string) (KeygenLicense, error) {
					return KeygenLicense{ID: "license-1", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: now.Add(time.Hour), BusinessExpiresAt: now.Add(time.Hour), OwnerID: "user-id", ProductID: "product-1"}, nil
				},
				heartbeatFn: func(context.Context, string, string) error { return nil },
				checkoutFn:  func(context.Context, string, string, int) (KeygenMachineFile, error) { return tc.file, nil },
			}
			s := newConfiguredV2TestServer(t, api)
			body, _ := json.Marshal(V2LeaseRequest{Product: productCode, MachineID: "machine-1", DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components(), ManifestSHA256: strings.Repeat("E", 64), Challenge: strings.Repeat("f", 43)})
			req := httptest.NewRequest(http.MethodPost, "/api/v2/lease", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer user-token")
			rr := httptest.NewRecorder()
			s.handleV2Lease(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestV2LeaseRejectsMachineUserComponentsAndExpiredLicenseMismatch(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name       string
		user       KeygenUser
		machine    KeygenMachine
		license    KeygenLicense
		wantStatus int
	}{
		{name: "other user", user: KeygenUser{ID: "current-user", Status: "ACTIVE"}, machine: KeygenMachine{ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "other-user", Components: validV2Components()}, license: KeygenLicense{ID: "license-1", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: now.Add(time.Hour), OwnerID: "other-user", ProductID: "product-1"}, wantStatus: http.StatusForbidden},
		{name: "physical minority", user: KeygenUser{ID: "user-id", Status: "ACTIVE"}, machine: KeygenMachine{ID: "machine-1", Fingerprint: strings.Repeat("F", 64), LicenseID: "license-1", OwnerID: "user-id", Components: fivePhysicalComponents()}, license: KeygenLicense{ID: "license-1", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: now.Add(time.Hour), OwnerID: "user-id", ProductID: "product-1"}, wantStatus: http.StatusForbidden},
		{name: "expired license", user: KeygenUser{ID: "user-id", Status: "ACTIVE"}, machine: KeygenMachine{ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id", Components: validV2Components()}, license: KeygenLicense{ID: "license-1", Status: "ACTIVE", Plan: "YEAR", Price: 128, ExpiresAt: now.Add(-time.Hour), OwnerID: "user-id", ProductID: "product-1"}, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkoutCalled := false
			api := &fakeKeygenAPI{
				currentUserFn: func(context.Context, string) (KeygenUser, error) { return tc.user, nil },
				getMachineFn:  func(context.Context, string, string) (KeygenMachine, error) { return tc.machine, nil },
				getLicenseFn:  func(context.Context, string, string) (KeygenLicense, error) { return tc.license, nil },
				checkoutFn: func(context.Context, string, string, int) (KeygenMachineFile, error) {
					checkoutCalled = true
					return KeygenMachineFile{}, nil
				},
			}
			s := newConfiguredV2TestServer(t, api)
			body, _ := json.Marshal(V2LeaseRequest{Product: productCode, MachineID: "machine-1", DeviceFingerprint: strings.Repeat("D", 64), Components: validV2Components(), ManifestSHA256: strings.Repeat("E", 64), Challenge: strings.Repeat("f", 43)})
			req := httptest.NewRequest(http.MethodPost, "/api/v2/lease", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer user-token")
			rr := httptest.NewRecorder()
			s.handleV2Lease(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
			if checkoutCalled {
				t.Fatal("checkout was called for mismatched lease relationship")
			}
		})
	}
}

func TestV2LogoutRevokesBearerToken(t *testing.T) {
	called := false
	api := &fakeKeygenAPI{
		revokeTokenFn: func(_ context.Context, token string) error {
			called = true
			if token != "user-token" {
				t.Fatalf("token mismatch")
			}
			return nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/logout", strings.NewReader(`{"product":"DEMO-PRODUCT"}`))
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Logout(rr, req)

	if rr.Code != http.StatusOK || !called {
		t.Fatalf("status=%d called=%v body=%s", rr.Code, called, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "user-token") {
		t.Fatalf("response leaked token: %s", rr.Body.String())
	}
}
