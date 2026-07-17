package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	keygenJSONAPIContentType = "application/vnd.api+json"
	keygenInternalHost       = "keygen.ql.invalid"
	keygenCheckoutTTLSeconds = 3600
	maxKeygenResponseBytes   = 1024 * 1024
)

var keygenIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

var keygenSHA256Pattern = regexp.MustCompile(`^[A-F0-9]{64}$`)

var keygenComponentNamePattern = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

var ErrKeygenLicenseNotFound = errors.New("license not found")

var ErrKeygenAmbiguous = errors.New("ambiguous authorization state")

var ErrKeygenDeviceMismatch = errors.New("device binding mismatch")

type KeygenAPI interface {
	Login(context.Context, string, string) (KeygenSession, error)
	CurrentUser(context.Context, string) (KeygenUser, error)
	ResolveLicense(context.Context, string, string, string, DeviceBinding) (KeygenLicenseResolution, error)
	EnsureMachine(context.Context, string, KeygenLicense, DeviceBinding) (KeygenMachine, error)
	GetMachine(context.Context, string, string) (KeygenMachine, error)
	GetLicense(context.Context, string, string) (KeygenLicense, error)
	Heartbeat(context.Context, string, string) error
	Checkout(context.Context, string, string, int) (KeygenMachineFile, error)
	RevokeToken(context.Context, string) error
}

type KeygenSession struct {
	Token   string
	TokenID string
	UserID  string
}

type KeygenUser struct {
	ID     string
	Status string
}

type KeygenLicense struct {
	ID                string
	Key               string
	Status            string
	Plan              string
	Price             int
	ExpiresAt         time.Time
	BusinessExpiresAt time.Time
	OwnerID           string
	ProductID         string
}

type KeygenLicenseResolution struct {
	License KeygenLicense
	Machine *KeygenMachine
}

type DeviceBinding struct {
	Fingerprint string            `json:"device_fingerprint"`
	Components  map[string]string `json:"components"`
}

type KeygenMachine struct {
	ID          string
	Fingerprint string
	LicenseID   string
	OwnerID     string
	Components  map[string]string
}

type KeygenMachineFile struct {
	Certificate string
	Algorithm   string
	TTL         int
	ExpiresAt   time.Time
	IssuedAt    time.Time
}

type KeygenUpstreamError struct {
	StatusCode int
}

func (e *KeygenUpstreamError) Error() string {
	return fmt.Sprintf("keygen request failed with status %d", e.StatusCode)
}

type keygenClient struct {
	baseURL   *url.URL
	accountID string
	productID string
	http      *http.Client
}

type keygenLicenseResource struct {
	ID         string `json:"id"`
	Attributes struct {
		Key      string `json:"key"`
		Expiry   string `json:"expiry"`
		Status   string `json:"status"`
		Metadata struct {
			Plan              string `json:"plan"`
			Price             int    `json:"price"`
			BusinessExpiresAt string `json:"businessExpiresAt"`
		} `json:"metadata"`
	} `json:"attributes"`
	Relationships struct {
		Owner struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"owner"`
		Product struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"product"`
	} `json:"relationships"`
}

type keygenMachineResource struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
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
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"components"`
	} `json:"relationships"`
}

type keygenComponentResource struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
	} `json:"attributes"`
	Relationships struct {
		Machine struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"machine"`
	} `json:"relationships"`
}

func newKeygenClient(baseURL, accountID, productID string) (*keygenClient, error) {
	parsed, err := validateLoopbackBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if !keygenIDPattern.MatchString(accountID) || !keygenIDPattern.MatchString(productID) {
		return nil, fmt.Errorf("invalid Keygen configuration")
	}
	return &keygenClient{
		baseURL:   parsed,
		accountID: accountID,
		productID: productID,
		http: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func validateLoopbackBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Keygen base URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid Keygen base URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("invalid Keygen base URL")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	isLoopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		isLoopback = ip.IsLoopback()
	}
	if !isLoopback {
		return nil, fmt.Errorf("Keygen base URL must be loopback")
	}
	parsed.Path = ""
	return parsed, nil
}

func (c *keygenClient) Login(ctx context.Context, email, password string) (KeygenSession, error) {
	var doc struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Token string `json:"token"`
			} `json:"attributes"`
			Relationships struct {
				Bearer struct {
					Data struct {
						Type string `json:"type"`
						ID   string `json:"id"`
					} `json:"data"`
				} `json:"bearer"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodPost, c.accountPath("tokens"), nil, "", email, password, nil, &doc); err != nil {
		return KeygenSession{}, err
	}
	if doc.Data.ID == "" || doc.Data.Attributes.Token == "" || doc.Data.Relationships.Bearer.Data.Type != "users" || doc.Data.Relationships.Bearer.Data.ID == "" {
		return KeygenSession{}, fmt.Errorf("invalid Keygen response")
	}
	return KeygenSession{
		Token:   doc.Data.Attributes.Token,
		TokenID: doc.Data.ID,
		UserID:  doc.Data.Relationships.Bearer.Data.ID,
	}, nil
}

func (c *keygenClient) CurrentUser(ctx context.Context, token string) (KeygenUser, error) {
	if token == "" {
		return KeygenUser{}, fmt.Errorf("invalid user request")
	}
	var profile struct {
		Data struct {
			Type       string `json:"type"`
			ID         string `json:"id"`
			Attributes struct {
				Status string `json:"status"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.accountPath("profile"), nil, token, "", "", nil, &profile); err != nil {
		return KeygenUser{}, err
	}
	if profile.Data.Type != "users" || !keygenIDPattern.MatchString(profile.Data.ID) {
		return KeygenUser{}, fmt.Errorf("invalid Keygen response")
	}
	return KeygenUser{ID: profile.Data.ID, Status: strings.ToUpper(strings.TrimSpace(profile.Data.Attributes.Status))}, nil
}

func (c *keygenClient) Checkout(ctx context.Context, token, machineID string, ttl int) (KeygenMachineFile, error) {
	if token == "" || !keygenIDPattern.MatchString(machineID) || ttl != keygenCheckoutTTLSeconds {
		return KeygenMachineFile{}, fmt.Errorf("invalid checkout request")
	}
	body := struct {
		Meta struct {
			TTL int `json:"ttl"`
		} `json:"meta"`
	}{}
	body.Meta.TTL = keygenCheckoutTTLSeconds
	var doc struct {
		Data struct {
			Attributes struct {
				Certificate string    `json:"certificate"`
				Algorithm   string    `json:"algorithm"`
				TTL         int       `json:"ttl"`
				Expiry      time.Time `json:"expiry"`
				Issued      time.Time `json:"issued"`
			} `json:"attributes"`
		} `json:"data"`
	}
	path := c.accountPath("machines", machineID, "actions", "check-out")
	if err := c.doJSON(ctx, http.MethodPost, path, nil, token, "", "", body, &doc); err != nil {
		return KeygenMachineFile{}, err
	}
	attrs := doc.Data.Attributes
	if attrs.Certificate == "" || attrs.Algorithm == "" || attrs.TTL != keygenCheckoutTTLSeconds || attrs.Expiry.IsZero() || attrs.Issued.IsZero() {
		return KeygenMachineFile{}, fmt.Errorf("invalid Keygen response")
	}
	return KeygenMachineFile{
		Certificate: attrs.Certificate,
		Algorithm:   attrs.Algorithm,
		TTL:         attrs.TTL,
		ExpiresAt:   attrs.Expiry,
		IssuedAt:    attrs.Issued,
	}, nil
}

func (c *keygenClient) accountPath(parts ...string) string {
	return "/v1/accounts/" + c.accountID + "/" + strings.Join(parts, "/")
}

func (c *keygenClient) doJSON(ctx context.Context, method, path string, query url.Values, bearer, basicUser, basicPassword string, body, dst any) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode Keygen request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	endpoint := *c.baseURL
	endpoint.Path = path
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return fmt.Errorf("create Keygen request: %w", err)
	}
	req.Header.Set("Accept", keygenJSONAPIContentType)
	req.Header.Set("Content-Type", keygenJSONAPIContentType)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Host = keygenInternalHost
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPassword)
	} else if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Keygen unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxKeygenResponseBytes))
		return &KeygenUpstreamError{StatusCode: resp.StatusCode}
	}
	if dst == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	limited := io.LimitReader(resp.Body, maxKeygenResponseBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil || len(payload) > maxKeygenResponseBytes {
		return fmt.Errorf("invalid Keygen response")
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("invalid Keygen response")
	}
	return nil
}

func (c *keygenClient) ResolveLicense(ctx context.Context, token, productID, cardKey string, binding DeviceBinding) (KeygenLicenseResolution, error) {
	if token == "" || productID != c.productID || !validDeviceBinding(binding.Fingerprint, binding.Components) {
		return KeygenLicenseResolution{}, fmt.Errorf("invalid license request")
	}
	var doc struct {
		Data []keygenLicenseResource `json:"data"`
	}
	query := url.Values{"product": {c.productID}}
	if err := c.doJSON(ctx, http.MethodGet, c.accountPath("licenses"), query, token, "", "", nil, &doc); err != nil {
		return KeygenLicenseResolution{}, err
	}
	wantedCard := strings.TrimSpace(cardKey)
	licenses := make([]KeygenLicense, 0, len(doc.Data))
	licensesByID := make(map[string]KeygenLicense, len(doc.Data))
	for i := range doc.Data {
		candidate := doc.Data[i]
		if candidate.Relationships.Product.Data.Type != "products" || candidate.Relationships.Product.Data.ID != c.productID || candidate.Relationships.Owner.Data.Type != "users" || candidate.Relationships.Owner.Data.ID == "" {
			continue
		}
		license, err := keygenLicenseFromResource(candidate, c.productID)
		if err != nil {
			return KeygenLicenseResolution{}, err
		}
		if _, duplicate := licensesByID[license.ID]; duplicate {
			return KeygenLicenseResolution{}, fmt.Errorf("invalid Keygen response")
		}
		licenses = append(licenses, license)
		licensesByID[license.ID] = license
	}

	if wantedCard != "" {
		var selected *KeygenLicense
		for i := range licenses {
			if licenses[i].Key != wantedCard {
				continue
			}
			if selected != nil {
				return KeygenLicenseResolution{}, ErrKeygenAmbiguous
			}
			selected = &licenses[i]
		}
		if selected == nil {
			return KeygenLicenseResolution{}, ErrKeygenLicenseNotFound
		}
		return KeygenLicenseResolution{License: *selected}, nil
	}

	machines, err := c.listMachines(ctx, token, nil)
	if err != nil {
		return KeygenLicenseResolution{}, err
	}
	selectedPriority := 0
	selectedIndex := -1
	ambiguous := false
	for i := range machines {
		machine := &machines[i]
		license, ok := licensesByID[machine.LicenseID]
		if !ok || machine.OwnerID != license.OwnerID || !matchesPhysicalMajority(machine.Components, binding.Components) {
			continue
		}
		priority := licensePlanPriority(license.Plan)
		if priority == 0 {
			continue
		}
		if priority > selectedPriority {
			selectedPriority = priority
			selectedIndex = i
			ambiguous = false
		} else if priority == selectedPriority {
			ambiguous = true
		}
	}
	if selectedIndex >= 0 {
		if ambiguous {
			return KeygenLicenseResolution{}, ErrKeygenAmbiguous
		}
		machine := machines[selectedIndex]
		return KeygenLicenseResolution{
			License: licensesByID[machine.LicenseID],
			Machine: &machine,
		}, nil
	}

	var trial *KeygenLicense
	for i := range licenses {
		if licenses[i].Plan != "TRIAL" {
			continue
		}
		if trial != nil {
			return KeygenLicenseResolution{}, ErrKeygenAmbiguous
		}
		trial = &licenses[i]
	}
	if trial == nil {
		return KeygenLicenseResolution{}, ErrKeygenLicenseNotFound
	}
	return KeygenLicenseResolution{License: *trial}, nil
}

func licensePlanPriority(plan string) int {
	switch plan {
	case "FOREVER":
		return 3
	case "YEAR":
		return 2
	case "TRIAL":
		return 1
	default:
		return 0
	}
}

func keygenLicenseFromResource(resource keygenLicenseResource, expectedProductID string) (KeygenLicense, error) {
	if !keygenIDPattern.MatchString(resource.ID) || resource.Attributes.Key == "" || resource.Relationships.Owner.Data.Type != "users" || !keygenIDPattern.MatchString(resource.Relationships.Owner.Data.ID) || resource.Relationships.Product.Data.Type != "products" || resource.Relationships.Product.Data.ID != expectedProductID {
		return KeygenLicense{}, fmt.Errorf("invalid Keygen response")
	}
	expiresAt, err := parseOptionalKeygenTime(resource.Attributes.Expiry)
	if err != nil {
		return KeygenLicense{}, fmt.Errorf("invalid Keygen response")
	}
	businessExpiresAt, err := parseOptionalKeygenTime(resource.Attributes.Metadata.BusinessExpiresAt)
	if err != nil {
		return KeygenLicense{}, fmt.Errorf("invalid Keygen response")
	}
	return KeygenLicense{
		ID:                resource.ID,
		Key:               resource.Attributes.Key,
		Status:            strings.ToUpper(strings.TrimSpace(resource.Attributes.Status)),
		Plan:              strings.ToUpper(strings.TrimSpace(resource.Attributes.Metadata.Plan)),
		Price:             resource.Attributes.Metadata.Price,
		ExpiresAt:         expiresAt,
		BusinessExpiresAt: businessExpiresAt,
		OwnerID:           resource.Relationships.Owner.Data.ID,
		ProductID:         resource.Relationships.Product.Data.ID,
	}, nil
}

func (c *keygenClient) GetLicense(ctx context.Context, token, licenseID string) (KeygenLicense, error) {
	if token == "" || !keygenIDPattern.MatchString(licenseID) {
		return KeygenLicense{}, fmt.Errorf("invalid license request")
	}
	var doc struct {
		Data keygenLicenseResource `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.accountPath("licenses", licenseID), nil, token, "", "", nil, &doc); err != nil {
		return KeygenLicense{}, err
	}
	if doc.Data.ID != licenseID {
		return KeygenLicense{}, fmt.Errorf("invalid Keygen response")
	}
	return keygenLicenseFromResource(doc.Data, c.productID)
}

func parseOptionalKeygenTime(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time")
}

func (c *keygenClient) EnsureMachine(ctx context.Context, token string, license KeygenLicense, binding DeviceBinding) (KeygenMachine, error) {
	if token == "" || !keygenIDPattern.MatchString(license.ID) || !keygenIDPattern.MatchString(license.OwnerID) || license.ProductID != c.productID || !validDeviceBinding(binding.Fingerprint, binding.Components) {
		return KeygenMachine{}, fmt.Errorf("invalid machine request")
	}
	componentNames := make([]string, 0, len(binding.Components))
	for name := range binding.Components {
		componentNames = append(componentNames, name)
	}
	sort.Strings(componentNames)

	machines, err := c.listMachines(ctx, token, url.Values{"license": {license.ID}})
	if err != nil {
		return KeygenMachine{}, err
	}
	matching := make([]KeygenMachine, 0, len(machines))
	for _, machine := range machines {
		if machine.LicenseID != license.ID || machine.OwnerID != license.OwnerID {
			return KeygenMachine{}, fmt.Errorf("invalid Keygen response")
		}
		if matchesPhysicalMajority(machine.Components, binding.Components) {
			matching = append(matching, machine)
		}
	}
	if len(matching) > 1 {
		return KeygenMachine{}, ErrKeygenAmbiguous
	}
	if len(matching) == 1 {
		return matching[0], nil
	}
	if len(machines) != 0 {
		return KeygenMachine{}, ErrKeygenDeviceMismatch
	}

	type componentInput struct {
		Type       string `json:"type"`
		Attributes struct {
			Name        string `json:"name"`
			Fingerprint string `json:"fingerprint"`
		} `json:"attributes"`
	}
	body := struct {
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
					Data []componentInput `json:"data"`
				} `json:"components"`
			} `json:"relationships"`
		} `json:"data"`
	}{}
	body.Data.Type = "machines"
	body.Data.Attributes.Fingerprint = binding.Fingerprint
	body.Data.Relationships.License.Data.Type = "licenses"
	body.Data.Relationships.License.Data.ID = license.ID
	body.Data.Relationships.Owner.Data.Type = "users"
	body.Data.Relationships.Owner.Data.ID = license.OwnerID
	for _, name := range componentNames {
		component := componentInput{Type: "components"}
		component.Attributes.Name = name
		component.Attributes.Fingerprint = binding.Components[name]
		body.Data.Relationships.Components.Data = append(body.Data.Relationships.Components.Data, component)
	}
	var created struct {
		Data keygenMachineResource `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodPost, c.accountPath("machines"), nil, token, "", "", body, &created); err != nil {
		return KeygenMachine{}, err
	}
	machine, err := keygenMachineFromResource(created.Data)
	if err != nil || machine.Fingerprint != binding.Fingerprint || machine.LicenseID != license.ID || machine.OwnerID != license.OwnerID {
		return KeygenMachine{}, fmt.Errorf("invalid Keygen response")
	}
	machine.Components = cloneDeviceComponents(binding.Components)
	return machine, nil
}

func keygenMachineFromResource(resource keygenMachineResource) (KeygenMachine, error) {
	if resource.Type != "machines" || !keygenIDPattern.MatchString(resource.ID) || !keygenSHA256Pattern.MatchString(resource.Attributes.Fingerprint) || resource.Relationships.License.Data.Type != "licenses" || !keygenIDPattern.MatchString(resource.Relationships.License.Data.ID) || resource.Relationships.Owner.Data.Type != "users" || !keygenIDPattern.MatchString(resource.Relationships.Owner.Data.ID) {
		return KeygenMachine{}, fmt.Errorf("invalid Keygen response")
	}
	return KeygenMachine{
		ID:          resource.ID,
		Fingerprint: resource.Attributes.Fingerprint,
		LicenseID:   resource.Relationships.License.Data.ID,
		OwnerID:     resource.Relationships.Owner.Data.ID,
	}, nil
}

func cloneDeviceComponents(components map[string]string) map[string]string {
	cloned := make(map[string]string, len(components))
	for name, fingerprint := range components {
		cloned[name] = fingerprint
	}
	return cloned
}

func parseKeygenMachines(resources []keygenMachineResource, included []keygenComponentResource) ([]KeygenMachine, error) {
	machines := make([]KeygenMachine, len(resources))
	machineIndexes := make(map[string]int, len(resources))
	expectedComponents := make(map[string]map[string]struct{}, len(resources))
	for i, resource := range resources {
		machine, err := keygenMachineFromResource(resource)
		if err != nil {
			return nil, err
		}
		if _, duplicate := machineIndexes[machine.ID]; duplicate {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		if resource.Relationships.Components.Data != nil {
			machine.Components = make(map[string]string, len(resource.Relationships.Components.Data))
		}
		machines[i] = machine
		machineIndexes[machine.ID] = i
		if resource.Relationships.Components.Data == nil {
			continue
		}
		linkages := make(map[string]struct{}, len(resource.Relationships.Components.Data))
		for _, linkage := range resource.Relationships.Components.Data {
			if linkage.Type != "components" || !keygenIDPattern.MatchString(linkage.ID) {
				return nil, fmt.Errorf("invalid Keygen response")
			}
			if _, duplicate := linkages[linkage.ID]; duplicate {
				return nil, fmt.Errorf("invalid Keygen response")
			}
			linkages[linkage.ID] = struct{}{}
		}
		expectedComponents[machine.ID] = linkages
	}

	seenComponentIDs := make(map[string]struct{}, len(included))
	for _, component := range included {
		machineID := component.Relationships.Machine.Data.ID
		machineIndex, ok := machineIndexes[machineID]
		if component.Type != "components" || !keygenIDPattern.MatchString(component.ID) ||
			component.Relationships.Machine.Data.Type != "machines" || !ok ||
			!keygenComponentNamePattern.MatchString(component.Attributes.Name) ||
			!keygenSHA256Pattern.MatchString(component.Attributes.Fingerprint) {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		expectedForMachine, hasLinkages := expectedComponents[machineID]
		if !hasLinkages {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		if _, expected := expectedForMachine[component.ID]; !expected {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		if _, duplicate := seenComponentIDs[component.ID]; duplicate {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		seenComponentIDs[component.ID] = struct{}{}
		if _, duplicate := machines[machineIndex].Components[component.Attributes.Name]; duplicate {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		machines[machineIndex].Components[component.Attributes.Name] = component.Attributes.Fingerprint
	}

	for i := range machines {
		if machines[i].Components != nil && (len(machines[i].Components) != len(expectedComponents[machines[i].ID]) || !validPhysicalComponents(machines[i].Components)) {
			return nil, fmt.Errorf("invalid Keygen response")
		}
	}
	return machines, nil
}

func parseKeygenMachineComponents(machineID string, resources []keygenComponentResource) (map[string]string, error) {
	if !keygenIDPattern.MatchString(machineID) {
		return nil, fmt.Errorf("invalid Keygen response")
	}
	components := make(map[string]string, len(resources))
	seenIDs := make(map[string]struct{}, len(resources))
	for _, component := range resources {
		if component.Type != "components" || !keygenIDPattern.MatchString(component.ID) ||
			component.Relationships.Machine.Data.Type != "machines" || component.Relationships.Machine.Data.ID != machineID ||
			!keygenComponentNamePattern.MatchString(component.Attributes.Name) ||
			!keygenSHA256Pattern.MatchString(component.Attributes.Fingerprint) {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		if _, duplicate := seenIDs[component.ID]; duplicate {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		seenIDs[component.ID] = struct{}{}
		if _, duplicate := components[component.Attributes.Name]; duplicate {
			return nil, fmt.Errorf("invalid Keygen response")
		}
		components[component.Attributes.Name] = component.Attributes.Fingerprint
	}
	if !validPhysicalComponents(components) {
		return nil, fmt.Errorf("invalid Keygen response")
	}
	return components, nil
}

func (c *keygenClient) getMachineComponents(ctx context.Context, token, machineID string) (map[string]string, error) {
	var doc struct {
		Data []keygenComponentResource `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.accountPath("machines", machineID, "components"), nil, token, "", "", nil, &doc); err != nil {
		return nil, err
	}
	return parseKeygenMachineComponents(machineID, doc.Data)
}

func (c *keygenClient) listMachines(ctx context.Context, token string, filters url.Values) ([]KeygenMachine, error) {
	if token == "" {
		return nil, fmt.Errorf("invalid machine request")
	}
	query := make(url.Values, len(filters)+1)
	for name, values := range filters {
		query[name] = append([]string(nil), values...)
	}
	query.Set("include", "components")
	var doc struct {
		Data     []keygenMachineResource   `json:"data"`
		Included []keygenComponentResource `json:"included"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.accountPath("machines"), query, token, "", "", nil, &doc); err != nil {
		return nil, err
	}
	machines, err := parseKeygenMachines(doc.Data, doc.Included)
	if err != nil {
		return nil, err
	}
	for i := range machines {
		if machines[i].Components != nil {
			continue
		}
		components, err := c.getMachineComponents(ctx, token, machines[i].ID)
		if err != nil {
			return nil, err
		}
		machines[i].Components = components
	}
	return machines, nil
}

func (c *keygenClient) GetMachine(ctx context.Context, token, machineID string) (KeygenMachine, error) {
	if token == "" || !keygenIDPattern.MatchString(machineID) {
		return KeygenMachine{}, fmt.Errorf("invalid machine request")
	}
	var doc struct {
		Data     keygenMachineResource     `json:"data"`
		Included []keygenComponentResource `json:"included"`
	}
	query := url.Values{"include": {"components"}}
	if err := c.doJSON(ctx, http.MethodGet, c.accountPath("machines", machineID), query, token, "", "", nil, &doc); err != nil {
		return KeygenMachine{}, err
	}
	if doc.Data.ID != machineID {
		return KeygenMachine{}, fmt.Errorf("invalid Keygen response")
	}
	machines, err := parseKeygenMachines([]keygenMachineResource{doc.Data}, doc.Included)
	if err != nil || len(machines) != 1 {
		return KeygenMachine{}, fmt.Errorf("invalid Keygen response")
	}
	if machines[0].Components == nil {
		machines[0].Components, err = c.getMachineComponents(ctx, token, machineID)
		if err != nil {
			return KeygenMachine{}, err
		}
	}
	return machines[0], nil
}

func (c *keygenClient) Heartbeat(ctx context.Context, token, machineID string) error {
	if token == "" || !keygenIDPattern.MatchString(machineID) {
		return fmt.Errorf("invalid heartbeat request")
	}
	var doc struct {
		Data struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"data"`
	}
	path := c.accountPath("machines", machineID, "actions", "ping")
	if err := c.doJSON(ctx, http.MethodPost, path, nil, token, "", "", nil, &doc); err != nil {
		return err
	}
	if doc.Data.Type != "machines" || doc.Data.ID != machineID {
		return fmt.Errorf("invalid Keygen response")
	}
	return nil
}

func (c *keygenClient) RevokeToken(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	var profile struct {
		Meta struct {
			TokenID string `json:"tokenId"`
		} `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.accountPath("profile"), nil, token, "", "", nil, &profile); err != nil {
		if isAlreadyRevokedError(err) {
			return nil
		}
		return err
	}
	if !keygenIDPattern.MatchString(profile.Meta.TokenID) {
		return fmt.Errorf("invalid Keygen response")
	}
	err := c.doJSON(ctx, http.MethodDelete, c.accountPath("tokens", profile.Meta.TokenID), nil, token, "", "", nil, nil)
	if isAlreadyRevokedError(err) {
		return nil
	}
	return err
}

func isAlreadyRevokedError(err error) bool {
	var upstream *KeygenUpstreamError
	return errors.As(err, &upstream) && (upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusNotFound)
}
