package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func newTestKeygenClient(t *testing.T, baseURL, accountID, productID string, httpClient *http.Client) *keygenClient {
	t.Helper()
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse test URL: %v", err)
	}
	return &keygenClient{
		baseURL:   parsed,
		accountID: accountID,
		productID: productID,
		http:      httpClient,
	}
}

type testMachineFixture struct {
	ID                 string
	Fingerprint        string
	LicenseID          string
	OwnerID            string
	Components         map[string]string
	ComponentMachineID string
}

type testLicenseFixture struct {
	ID        string
	Key       string
	Status    string
	Plan      string
	Price     int
	Expiry    string
	OwnerID   string
	ProductID string
}

func testLicenseDocument(t *testing.T, fixtures []testLicenseFixture) string {
	t.Helper()
	resources := make([]any, 0, len(fixtures))
	for _, fixture := range fixtures {
		metadata := map[string]any{"plan": fixture.Plan, "price": fixture.Price}
		if fixture.Expiry != "" {
			metadata["businessExpiresAt"] = fixture.Expiry
		}
		resources = append(resources, map[string]any{
			"type": "licenses",
			"id":   fixture.ID,
			"attributes": map[string]any{
				"key":      fixture.Key,
				"status":   fixture.Status,
				"expiry":   fixture.Expiry,
				"metadata": metadata,
			},
			"relationships": map[string]any{
				"owner":   map[string]any{"data": map[string]any{"type": "users", "id": fixture.OwnerID}},
				"product": map[string]any{"data": map[string]any{"type": "products", "id": fixture.ProductID}},
			},
		})
	}
	payload, err := json.Marshal(map[string]any{"data": resources})
	if err != nil {
		t.Fatalf("marshal license document: %v", err)
	}
	return string(payload)
}

func testMachineDocument(t *testing.T, fixtures []testMachineFixture, single bool) string {
	t.Helper()
	resources := make([]any, 0, len(fixtures))
	included := make([]any, 0)
	for _, fixture := range fixtures {
		names := make([]string, 0, len(fixture.Components))
		for name := range fixture.Components {
			names = append(names, name)
		}
		sort.Strings(names)
		linkages := make([]any, 0, len(names))
		for _, name := range names {
			componentID := fixture.ID + "-" + name
			linkages = append(linkages, map[string]any{"type": "components", "id": componentID})
			machineID := fixture.ComponentMachineID
			if machineID == "" {
				machineID = fixture.ID
			}
			included = append(included, map[string]any{
				"type": "components",
				"id":   componentID,
				"attributes": map[string]any{
					"name":        name,
					"fingerprint": fixture.Components[name],
				},
				"relationships": map[string]any{
					"machine": map[string]any{
						"data": map[string]any{"type": "machines", "id": machineID},
					},
				},
			})
		}
		resources = append(resources, map[string]any{
			"type": "machines",
			"id":   fixture.ID,
			"attributes": map[string]any{
				"fingerprint": fixture.Fingerprint,
			},
			"relationships": map[string]any{
				"license": map[string]any{"data": map[string]any{"type": "licenses", "id": fixture.LicenseID}},
				"owner":   map[string]any{"data": map[string]any{"type": "users", "id": fixture.OwnerID}},
				"components": map[string]any{
					"data": linkages,
				},
			},
		})
	}
	var data any = resources
	if single {
		if len(resources) != 1 {
			t.Fatalf("single machine document needs one fixture")
		}
		data = resources[0]
	}
	payload, err := json.Marshal(map[string]any{"data": data, "included": included})
	if err != nil {
		t.Fatalf("marshal machine document: %v", err)
	}
	return string(payload)
}

func testMachineComponentDocument(t *testing.T, fixture testMachineFixture) string {
	t.Helper()
	resources := make([]any, 0, len(fixture.Components))
	names := make([]string, 0, len(fixture.Components))
	for name := range fixture.Components {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		resources = append(resources, map[string]any{
			"type": "components",
			"id":   fixture.ID + "-" + name,
			"attributes": map[string]any{
				"name":        name,
				"fingerprint": fixture.Components[name],
			},
			"relationships": map[string]any{
				"machine": map[string]any{
					"data": map[string]any{"type": "machines", "id": fixture.ID},
				},
			},
		})
	}
	payload, err := json.Marshal(map[string]any{"data": resources})
	if err != nil {
		t.Fatalf("marshal machine component document: %v", err)
	}
	return string(payload)
}

func validClientBinding() DeviceBinding {
	return DeviceBinding{
		Fingerprint: strings.Repeat("F", 64),
		Components:  validV2Components(),
	}
}

func newLicenseResolutionUpstream(
	t *testing.T,
	licenses []testLicenseFixture,
	machines []testMachineFixture,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		switch r.URL.Path {
		case "/v1/accounts/account-1/licenses":
			if r.Method != http.MethodGet || r.URL.Query().Get("product") != "product-1" {
				t.Fatalf("unexpected license request: %s %s", r.Method, r.URL.RequestURI())
			}
			_, _ = w.Write([]byte(testLicenseDocument(t, licenses)))
		case "/v1/accounts/account-1/machines":
			if r.Method != http.MethodGet || r.URL.Query().Get("include") != "components" {
				t.Fatalf("unexpected machine request: %s %s", r.Method, r.URL.RequestURI())
			}
			_, _ = w.Write([]byte(testMachineDocument(t, machines, false)))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
}

func TestKeygenClientLoginUsesTokenRouteAndBasicAuth(t *testing.T) {
	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost || r.URL.Path != "/v1/accounts/account-1/tokens" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "user1@accounts.license.invalid" || password != "test-password" {
			t.Fatalf("unexpected basic auth: username=%q ok=%v", username, ok)
		}
		if got := r.Header.Get("Accept"); got != keygenJSONAPIContentType {
			t.Fatalf("Accept = %q", got)
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("X-Forwarded-Proto = %q", got)
		}
		if r.Host != "keygen.ql.invalid" {
			t.Fatalf("Host = %q", r.Host)
		}
		if got := r.Header.Get("Authorization"); got == "Bearer test-password" {
			t.Fatal("password was sent as bearer token")
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"type":"tokens","id":"token-id","attributes":{"token":"user-token"},"relationships":{"bearer":{"data":{"type":"users","id":"user-id"}}}}}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	session, err := client.Login(context.Background(), "user1@accounts.license.invalid", "test-password")
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if !called {
		t.Fatal("upstream was not called")
	}
	if session.Token != "user-token" || session.TokenID != "token-id" || session.UserID != "user-id" {
		t.Fatalf("unexpected session: %#v", session)
	}
}

func TestKeygenClientCheckoutUsesFixedMachineRouteAndTTLWithoutPrivilegedIncludes(t *testing.T) {
	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/accounts/account-1/machines/machine-1/actions/check-out" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		var body struct {
			Meta struct {
				TTL     int             `json:"ttl"`
				Include json.RawMessage `json:"include"`
			} `json:"meta"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode checkout body: %v", err)
		}
		if body.Meta.TTL != keygenCheckoutTTLSeconds {
			t.Fatalf("ttl = %d", body.Meta.TTL)
		}
		if len(body.Meta.Include) != 0 {
			t.Fatalf("checkout requested privileged includes: %s", body.Meta.Include)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(`{"data":{"type":"machine-files","id":"file-1","attributes":{"certificate":"signed-machine-file","algorithm":"base64+ed25519","ttl":3600,"expiry":"` + expiry.Format(time.RFC3339) + `","issued":"` + expiry.Add(-time.Hour).Format(time.RFC3339) + `"}}}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	file, err := client.Checkout(context.Background(), "user-token", "machine-1", keygenCheckoutTTLSeconds)
	if err != nil {
		t.Fatalf("Checkout returned error: %v", err)
	}
	if file.Certificate != "signed-machine-file" || file.Algorithm != "base64+ed25519" || file.TTL != keygenCheckoutTTLSeconds || !file.ExpiresAt.Equal(expiry) {
		t.Fatalf("unexpected machine file: %#v", file)
	}
}

func TestKeygenClientCheckoutRejectsNonFixedTTLWithoutCallingUpstream(t *testing.T) {
	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	if _, err := client.Checkout(context.Background(), "user-token", "machine-1", 7200); err == nil {
		t.Fatal("Checkout accepted non-fixed TTL")
	}
	if called {
		t.Fatal("upstream was called for invalid TTL")
	}
}

func TestNewKeygenClientRejectsNonLoopbackBaseURL(t *testing.T) {
	if _, err := newKeygenClient("https://api.keygen.sh", "account-1", "product-1"); err == nil {
		t.Fatal("newKeygenClient accepted non-loopback base URL")
	}
}

func TestKeygenClientResolveLicenseUsesProductFilterAndSelectsTrial(t *testing.T) {
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		switch r.URL.Path {
		case "/v1/accounts/account-1/licenses":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			}
			if got := r.URL.Query(); len(got) != 1 || got.Get("product") != "product-1" {
				t.Fatalf("unexpected query: %v", got)
			}
			_, _ = w.Write([]byte(`{"data":[{"type":"licenses","id":"license-1","attributes":{"key":"TRIAL-KEY","expiry":"` + expires.Format(time.RFC3339) + `","status":"ACTIVE","metadata":{"plan":"TRIAL","price":0,"businessExpiresAt":"` + expires.Format(time.RFC3339) + `"}},"relationships":{"owner":{"data":{"type":"users","id":"user-id"}},"product":{"data":{"type":"products","id":"product-1"}}}}]}`))
		case "/v1/accounts/account-1/machines":
			if r.Method != http.MethodGet || r.URL.Query().Get("include") != "components" {
				t.Fatalf("unexpected machine lookup: %s %s", r.Method, r.URL.RequestURI())
			}
			_, _ = w.Write([]byte(`{"data":[],"included":[]}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	resolution, err := client.ResolveLicense(context.Background(), "user-token", "product-1", "", validClientBinding())
	if err != nil {
		t.Fatalf("ResolveLicense returned error: %v", err)
	}
	license := resolution.License
	if resolution.Machine != nil {
		t.Fatalf("unexpected existing machine: %#v", resolution.Machine)
	}
	if license.ID != "license-1" || license.Key != "TRIAL-KEY" || license.Plan != "TRIAL" || license.Price != 0 || license.Status != "ACTIVE" || license.OwnerID != "user-id" || license.ProductID != "product-1" || !license.ExpiresAt.Equal(expires) || !license.BusinessExpiresAt.Equal(expires) {
		t.Fatalf("unexpected license: %#v", license)
	}
}

func TestKeygenClientResolveLicenseSelectsExactPaidCard(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(`{"data":[{"type":"licenses","id":"trial-id","attributes":{"key":"TRIAL-KEY","status":"ACTIVE","metadata":{"plan":"TRIAL","price":0}},"relationships":{"owner":{"data":{"type":"users","id":"user-id"}},"product":{"data":{"type":"products","id":"product-1"}}}},{"type":"licenses","id":"year-id","attributes":{"key":"YEAR-KEY-123","status":"ACTIVE","metadata":{"plan":"YEAR","price":128}},"relationships":{"owner":{"data":{"type":"users","id":"user-id"}},"product":{"data":{"type":"products","id":"product-1"}}}}]}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	resolution, err := client.ResolveLicense(context.Background(), "user-token", "product-1", "YEAR-KEY-123", validClientBinding())
	if err != nil {
		t.Fatalf("ResolveLicense returned error: %v", err)
	}
	license := resolution.License
	if resolution.Machine != nil {
		t.Fatalf("paid card lookup unexpectedly returned a machine: %#v", resolution.Machine)
	}
	if license.ID != "year-id" || license.Plan != "YEAR" || license.Price != 128 {
		t.Fatalf("unexpected license: %#v", license)
	}
}

func TestKeygenClientResolveLicenseNoCardPrefersBoundPaidOverTrial(t *testing.T) {
	bound := fivePhysicalComponents()
	candidate := cloneComponents(bound)
	candidate["bios"] = strings.Repeat("1", 64)
	licenses := []testLicenseFixture{
		{ID: "trial-id", Key: "TRIAL-KEY", Status: "ACTIVE", Plan: "TRIAL", Price: 0, OwnerID: "user-id", ProductID: "product-1"},
		{ID: "year-id", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, OwnerID: "user-id", ProductID: "product-1"},
	}
	machines := []testMachineFixture{
		{ID: "trial-machine", Fingerprint: strings.Repeat("A", 64), LicenseID: "trial-id", OwnerID: "user-id", Components: bound},
		{ID: "year-machine", Fingerprint: strings.Repeat("B", 64), LicenseID: "year-id", OwnerID: "user-id", Components: bound},
	}
	upstream := newLicenseResolutionUpstream(t, licenses, machines)
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	resolution, err := client.ResolveLicense(context.Background(), "user-token", "product-1", "", DeviceBinding{Fingerprint: strings.Repeat("C", 64), Components: candidate})
	if err != nil {
		t.Fatalf("ResolveLicense returned error: %v", err)
	}
	if resolution.License.ID != "year-id" || resolution.Machine == nil || resolution.Machine.ID != "year-machine" || resolution.Machine.Fingerprint != strings.Repeat("B", 64) {
		t.Fatalf("unexpected resolution: %#v", resolution)
	}
}

func TestKeygenClientResolveLicenseNoCardPrefersForeverOverYear(t *testing.T) {
	bound := fivePhysicalComponents()
	licenses := []testLicenseFixture{
		{ID: "year-id", Key: "YEAR-KEY", Status: "ACTIVE", Plan: "YEAR", Price: 128, OwnerID: "user-id", ProductID: "product-1"},
		{ID: "forever-id", Key: "FOREVER-KEY", Status: "ACTIVE", Plan: "FOREVER", Price: 288, OwnerID: "user-id", ProductID: "product-1"},
	}
	machines := []testMachineFixture{
		{ID: "year-machine", Fingerprint: strings.Repeat("A", 64), LicenseID: "year-id", OwnerID: "user-id", Components: bound},
		{ID: "forever-machine", Fingerprint: strings.Repeat("B", 64), LicenseID: "forever-id", OwnerID: "user-id", Components: bound},
	}
	upstream := newLicenseResolutionUpstream(t, licenses, machines)
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	resolution, err := client.ResolveLicense(context.Background(), "user-token", "product-1", "", DeviceBinding{Fingerprint: strings.Repeat("C", 64), Components: bound})
	if err != nil {
		t.Fatalf("ResolveLicense returned error: %v", err)
	}
	if resolution.License.ID != "forever-id" || resolution.Machine == nil || resolution.Machine.ID != "forever-machine" {
		t.Fatalf("unexpected resolution: %#v", resolution)
	}
}

func TestKeygenClientResolveLicenseNoCardDoesNotFallBackFromBoundSuspendedPaid(t *testing.T) {
	bound := fivePhysicalComponents()
	licenses := []testLicenseFixture{
		{ID: "trial-id", Key: "TRIAL-KEY", Status: "ACTIVE", Plan: "TRIAL", Price: 0, OwnerID: "user-id", ProductID: "product-1"},
		{ID: "year-id", Key: "YEAR-KEY", Status: "SUSPENDED", Plan: "YEAR", Price: 128, OwnerID: "user-id", ProductID: "product-1"},
	}
	machines := []testMachineFixture{{ID: "year-machine", Fingerprint: strings.Repeat("A", 64), LicenseID: "year-id", OwnerID: "user-id", Components: bound}}
	upstream := newLicenseResolutionUpstream(t, licenses, machines)
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	resolution, err := client.ResolveLicense(context.Background(), "user-token", "product-1", "", DeviceBinding{Fingerprint: strings.Repeat("B", 64), Components: bound})
	if err != nil {
		t.Fatalf("ResolveLicense returned error: %v", err)
	}
	if resolution.License.ID != "year-id" || resolution.License.Status != "SUSPENDED" || resolution.Machine == nil {
		t.Fatalf("suspended paid license did not block trial fallback: %#v", resolution)
	}
}

func TestKeygenClientResolveLicenseNoCardRejectsAmbiguousHighestPlan(t *testing.T) {
	bound := fivePhysicalComponents()
	licenses := []testLicenseFixture{
		{ID: "year-1", Key: "YEAR-1", Status: "ACTIVE", Plan: "YEAR", Price: 128, OwnerID: "user-id", ProductID: "product-1"},
		{ID: "year-2", Key: "YEAR-2", Status: "ACTIVE", Plan: "YEAR", Price: 128, OwnerID: "user-id", ProductID: "product-1"},
	}
	machines := []testMachineFixture{
		{ID: "machine-1", Fingerprint: strings.Repeat("A", 64), LicenseID: "year-1", OwnerID: "user-id", Components: bound},
		{ID: "machine-2", Fingerprint: strings.Repeat("B", 64), LicenseID: "year-2", OwnerID: "user-id", Components: bound},
	}
	upstream := newLicenseResolutionUpstream(t, licenses, machines)
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	_, err := client.ResolveLicense(context.Background(), "user-token", "product-1", "", DeviceBinding{Fingerprint: strings.Repeat("C", 64), Components: bound})
	if !errors.Is(err, ErrKeygenAmbiguous) {
		t.Fatalf("ResolveLicense error = %v, want ErrKeygenAmbiguous", err)
	}
}

func TestKeygenClientErrorsDoNotExposeUpstreamBodyOrBearer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"upstream-secret-body"}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	_, err := client.ResolveLicense(context.Background(), "user-secret-token", "product-1", "", validClientBinding())
	if err == nil {
		t.Fatal("ResolveLicense succeeded")
	}
	if got := err.Error(); strings.Contains(got, "upstream-secret-body") || strings.Contains(got, "user-secret-token") {
		t.Fatalf("error leaked sensitive data: %q", got)
	}
}

func TestKeygenClientEnsureMachineReturnsExistingBinding(t *testing.T) {
	fingerprint := strings.Repeat("A", 64)
	components := map[string]string{
		"bios":        strings.Repeat("B", 64),
		"smbios":      strings.Repeat("C", 64),
		"system_disk": strings.Repeat("D", 64),
	}
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/machines" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		query := r.URL.Query()
		if len(query) != 2 || query.Get("license") != "license-1" || query.Get("include") != "components" {
			t.Fatalf("unexpected query: %v", query)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(testMachineDocument(t, []testMachineFixture{{
			ID:          "machine-1",
			Fingerprint: fingerprint,
			LicenseID:   "license-1",
			OwnerID:     "user-id",
			Components:  components,
		}}, false)))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	machine, err := client.EnsureMachine(context.Background(), "user-token", KeygenLicense{ID: "license-1", OwnerID: "user-id", ProductID: "product-1"}, DeviceBinding{Fingerprint: fingerprint, Components: components})
	if err != nil {
		t.Fatalf("EnsureMachine returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("upstream calls = %d", calls)
	}
	if machine.ID != "machine-1" || machine.Fingerprint != fingerprint || machine.LicenseID != "license-1" || machine.OwnerID != "user-id" || !reflect.DeepEqual(machine.Components, components) {
		t.Fatalf("unexpected machine: %#v", machine)
	}
}

func TestKeygenClientEnsureMachineLoadsComponentsFromNestedEndpoint(t *testing.T) {
	fingerprint := strings.Repeat("A", 64)
	fixture := testMachineFixture{
		ID:          "machine-1",
		Fingerprint: fingerprint,
		LicenseID:   "license-1",
		OwnerID:     "user-id",
		Components:  validV2Components(),
	}
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		switch calls {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/machines" || r.URL.Query().Get("license") != "license-1" {
				t.Fatalf("unexpected machine request: %s %s", r.Method, r.URL.RequestURI())
			}
			_, _ = w.Write([]byte(`{"data":[{"type":"machines","id":"machine-1","attributes":{"fingerprint":"` + fingerprint + `"},"relationships":{"license":{"data":{"type":"licenses","id":"license-1"}},"owner":{"data":{"type":"users","id":"user-id"}},"components":{"links":{"related":"/components"}}}}]}`))
		case 2:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/machines/machine-1/components" || r.URL.RawQuery != "" {
				t.Fatalf("unexpected component request: %s %s", r.Method, r.URL.RequestURI())
			}
			_, _ = w.Write([]byte(testMachineComponentDocument(t, fixture)))
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	machine, err := client.EnsureMachine(
		context.Background(),
		"user-token",
		KeygenLicense{ID: "license-1", OwnerID: "user-id", ProductID: "product-1"},
		DeviceBinding{Fingerprint: fingerprint, Components: fixture.Components})
	if err != nil {
		t.Fatalf("EnsureMachine returned error: %v", err)
	}
	if calls != 2 || !reflect.DeepEqual(machine.Components, fixture.Components) {
		t.Fatalf("calls=%d machine=%#v", calls, machine)
	}
}

func TestKeygenClientEnsureMachineReusesUniquePhysicalMajorityWithoutCreating(t *testing.T) {
	bound := fivePhysicalComponents()
	candidate := cloneComponents(bound)
	candidate["bios"] = strings.Repeat("1", 64)
	boundFingerprint := strings.Repeat("A", 64)
	candidateFingerprint := strings.Repeat("B", 64)
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/machines" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		if query := r.URL.Query(); len(query) != 2 || query.Get("license") != "license-1" || query.Get("include") != "components" {
			t.Fatalf("unexpected query: %v", query)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(testMachineDocument(t, []testMachineFixture{{
			ID:          "machine-1",
			Fingerprint: boundFingerprint,
			LicenseID:   "license-1",
			OwnerID:     "user-id",
			Components:  bound,
		}}, false)))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	machine, err := client.EnsureMachine(
		context.Background(),
		"user-token",
		KeygenLicense{ID: "license-1", OwnerID: "user-id", ProductID: "product-1"},
		DeviceBinding{Fingerprint: candidateFingerprint, Components: candidate})
	if err != nil {
		t.Fatalf("EnsureMachine returned error: %v", err)
	}
	if calls != 1 || machine.ID != "machine-1" || machine.Fingerprint != boundFingerprint || !reflect.DeepEqual(machine.Components, bound) {
		t.Fatalf("calls=%d machine=%#v", calls, machine)
	}
}

func TestKeygenClientEnsureMachineCreatesWithSortedComponents(t *testing.T) {
	fingerprint := strings.Repeat("A", 64)
	components := map[string]string{
		"system_disk": strings.Repeat("C", 64),
		"bios":        strings.Repeat("B", 64),
		"smbios":      strings.Repeat("D", 64),
	}
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		if calls == 1 {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/machines" {
				t.Fatalf("unexpected lookup: %s %s", r.Method, r.URL.RequestURI())
			}
			if query := r.URL.Query(); len(query) != 2 || query.Get("license") != "license-1" || query.Get("include") != "components" {
				t.Fatalf("unexpected lookup query: %v", query)
			}
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		if calls != 2 || r.Method != http.MethodPost || r.URL.Path != "/v1/accounts/account-1/machines" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected create: %s %s", r.Method, r.URL.RequestURI())
		}
		var body struct {
			Data struct {
				Type       string `json:"type"`
				Attributes struct {
					Fingerprint string `json:"fingerprint"`
				} `json:"attributes"`
				Relationships struct {
					License struct {
						Data struct {
							Type string `json:"type"`
							ID   string `json:"id"`
						} `json:"data"`
					} `json:"license"`
					Owner struct {
						Data struct {
							Type string `json:"type"`
							ID   string `json:"id"`
						} `json:"data"`
					} `json:"owner"`
					Components struct {
						Data []struct {
							Type       string `json:"type"`
							Attributes struct {
								Name        string `json:"name"`
								Fingerprint string `json:"fingerprint"`
							} `json:"attributes"`
						} `json:"data"`
					} `json:"components"`
				} `json:"relationships"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode create body: %v", err)
		}
		if body.Data.Type != "machines" || body.Data.Attributes.Fingerprint != fingerprint || body.Data.Relationships.License.Data.Type != "licenses" || body.Data.Relationships.License.Data.ID != "license-1" || body.Data.Relationships.Owner.Data.Type != "users" || body.Data.Relationships.Owner.Data.ID != "user-id" {
			t.Fatalf("unexpected create body: %#v", body)
		}
		gotNames := make([]string, 0, len(body.Data.Relationships.Components.Data))
		for _, component := range body.Data.Relationships.Components.Data {
			if component.Type != "components" || component.Attributes.Fingerprint != components[component.Attributes.Name] {
				t.Fatalf("unexpected component: %#v", component)
			}
			gotNames = append(gotNames, component.Attributes.Name)
		}
		if want := []string{"bios", "smbios", "system_disk"}; !reflect.DeepEqual(gotNames, want) {
			t.Fatalf("component names = %#v", gotNames)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"type":"machines","id":"machine-1","attributes":{"fingerprint":"` + fingerprint + `"},"relationships":{"license":{"data":{"type":"licenses","id":"license-1"}},"owner":{"data":{"type":"users","id":"user-id"}}}}}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	machine, err := client.EnsureMachine(context.Background(), "user-token", KeygenLicense{ID: "license-1", OwnerID: "user-id", ProductID: "product-1"}, DeviceBinding{Fingerprint: fingerprint, Components: components})
	if err != nil {
		t.Fatalf("EnsureMachine returned error: %v", err)
	}
	if calls != 2 || machine.ID != "machine-1" || !reflect.DeepEqual(machine.Components, components) {
		t.Fatalf("calls=%d machine=%#v", calls, machine)
	}
}

func TestKeygenClientRevokeTokenResolvesCurrentTokenIDThenDeletes(t *testing.T) {
	var calls []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch len(calls) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/profile" || r.URL.RawQuery != "" {
				t.Fatalf("unexpected profile request: %s %s", r.Method, r.URL.RequestURI())
			}
			w.Header().Set("Content-Type", keygenJSONAPIContentType)
			_, _ = w.Write([]byte(`{"data":{"type":"users","id":"user-id"},"meta":{"tokenId":"token-id"}}`))
		case 2:
			if r.Method != http.MethodDelete || r.URL.Path != "/v1/accounts/account-1/tokens/token-id" || r.URL.RawQuery != "" {
				t.Fatalf("unexpected revoke request: %s %s", r.Method, r.URL.RequestURI())
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	if err := client.RevokeToken(context.Background(), "user-token"); err != nil {
		t.Fatalf("RevokeToken returned error: %v", err)
	}
	if want := []string{"GET /v1/accounts/account-1/profile", "DELETE /v1/accounts/account-1/tokens/token-id"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestKeygenClientRevokeTokenTreatsUnauthorizedAsAlreadyRevoked(t *testing.T) {
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	if err := client.RevokeToken(context.Background(), "already-revoked-token"); err != nil {
		t.Fatalf("RevokeToken returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("upstream calls = %d", calls)
	}
}

func TestKeygenClientCurrentUserUsesProfileRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/profile" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(`{"data":{"type":"users","id":"user-id","attributes":{"status":"ACTIVE"}},"meta":{"tokenId":"token-id"}}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	user, err := client.CurrentUser(context.Background(), "user-token")
	if err != nil {
		t.Fatalf("CurrentUser returned error: %v", err)
	}
	if user.ID != "user-id" || user.Status != "ACTIVE" {
		t.Fatalf("unexpected user: %#v", user)
	}
}

func TestKeygenClientGetMachineUsesExactIDRoute(t *testing.T) {
	fingerprint := strings.Repeat("D", 64)
	components := validV2Components()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/machines/machine-1" || r.URL.Query().Get("include") != "components" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(testMachineDocument(t, []testMachineFixture{{ID: "machine-1", Fingerprint: fingerprint, LicenseID: "license-1", OwnerID: "user-id", Components: components}}, true)))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	machine, err := client.GetMachine(context.Background(), "user-token", "machine-1")
	if err != nil {
		t.Fatalf("GetMachine returned error: %v", err)
	}
	if machine.ID != "machine-1" || machine.Fingerprint != fingerprint || machine.LicenseID != "license-1" || machine.OwnerID != "user-id" || !reflect.DeepEqual(machine.Components, components) {
		t.Fatalf("unexpected machine: %#v", machine)
	}
}

func TestKeygenClientGetMachineRejectsIncompleteOrWronglyLinkedComponents(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture testMachineFixture
	}{
		{
			name: "too few physical components",
			fixture: testMachineFixture{
				ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id",
				Components: map[string]string{"bios": strings.Repeat("A", 64), "smbios": strings.Repeat("B", 64)},
			},
		},
		{
			name: "component linked to another machine",
			fixture: testMachineFixture{
				ID: "machine-1", Fingerprint: strings.Repeat("D", 64), LicenseID: "license-1", OwnerID: "user-id",
				Components: validV2Components(), ComponentMachineID: "machine-2",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", keygenJSONAPIContentType)
				_, _ = w.Write([]byte(testMachineDocument(t, []testMachineFixture{tc.fixture}, true)))
			}))
			defer upstream.Close()

			client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
			if _, err := client.GetMachine(context.Background(), "user-token", "machine-1"); err == nil {
				t.Fatal("GetMachine accepted invalid included components")
			}
		})
	}
}

func TestKeygenClientGetLicenseUsesExactIDRoute(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts/account-1/licenses/license-1" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(`{"data":{"type":"licenses","id":"license-1","attributes":{"key":"YEAR-KEY","expiry":"` + expires.Format(time.RFC3339) + `","status":"ACTIVE","metadata":{"plan":"YEAR","price":128,"businessExpiresAt":"` + expires.Format(time.RFC3339) + `"}},"relationships":{"owner":{"data":{"type":"users","id":"user-id"}},"product":{"data":{"type":"products","id":"product-1"}}}}}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	license, err := client.GetLicense(context.Background(), "user-token", "license-1")
	if err != nil {
		t.Fatalf("GetLicense returned error: %v", err)
	}
	if license.ID != "license-1" || license.OwnerID != "user-id" || license.ProductID != "product-1" || license.Plan != "YEAR" || license.Price != 128 || !license.ExpiresAt.Equal(expires) {
		t.Fatalf("unexpected license: %#v", license)
	}
}

func TestKeygenClientHeartbeatUsesExactActionRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/accounts/account-1/machines/machine-1/actions/ping" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", keygenJSONAPIContentType)
		_, _ = w.Write([]byte(`{"data":{"type":"machines","id":"machine-1"}}`))
	}))
	defer upstream.Close()

	client := newTestKeygenClient(t, upstream.URL, "account-1", "product-1", upstream.Client())
	if err := client.Heartbeat(context.Background(), "user-token", "machine-1"); err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
}
