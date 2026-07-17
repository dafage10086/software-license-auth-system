package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const maxV2RequestBodyBytes int64 = 32 * 1024

var accountUsernamePattern = regexp.MustCompile(`^[a-z0-9._-]{4,32}$`)

var paidCardPattern = regexp.MustCompile(`^[A-Z0-9-]{4,256}$`)

var leaseChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

var allowedDeviceComponents = map[string]struct{}{
	"smbios":       {},
	"baseboard":    {},
	"bios":         {},
	"system_disk":  {},
	"machine_guid": {},
	"device_key":   {},
}

type V2LoginRequest struct {
	Product       string `json:"product"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	ClientVersion string `json:"client_version"`
}

type V2LoginResponse struct {
	OK           bool   `json:"ok"`
	Message      string `json:"message"`
	SessionToken string `json:"session_token,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	Username     string `json:"username,omitempty"`
	ServerTime   string `json:"server_time"`
}

type V2ActivateRequest struct {
	Product           string            `json:"product"`
	CardKey           string            `json:"card_key,omitempty"`
	DeviceFingerprint string            `json:"device_fingerprint"`
	Components        map[string]string `json:"components"`
	ClientVersion     string            `json:"client_version"`
}

type V2ActivateResponse struct {
	OK                 bool   `json:"ok"`
	Message            string `json:"message"`
	UserID             string `json:"user_id,omitempty"`
	LicenseID          string `json:"license_id,omitempty"`
	MachineID          string `json:"machine_id,omitempty"`
	MachineFingerprint string `json:"machine_fingerprint"`
	Plan               string `json:"plan,omitempty"`
	Price              int    `json:"price,omitempty"`
	ExpiresAt          string `json:"expires_at,omitempty"`
	ServerTime         string `json:"server_time"`
}

type V2LeaseRequest struct {
	Product           string            `json:"product"`
	MachineID         string            `json:"machine_id"`
	DeviceFingerprint string            `json:"device_fingerprint"`
	Components        map[string]string `json:"components"`
	ManifestSHA256    string            `json:"manifest_sha256"`
	Challenge         string            `json:"challenge"`
	ClientVersion     string            `json:"client_version"`
}

type V2LeaseResponse struct {
	OK                   bool   `json:"ok"`
	Message              string `json:"message"`
	MachineFile          string `json:"machine_file,omitempty"`
	MachineFileExpiresAt string `json:"machine_file_expires_at,omitempty"`
	RefreshAfterSeconds  int    `json:"refresh_after_seconds,omitempty"`
	Challenge            string `json:"challenge,omitempty"`
	ManifestSHA256       string `json:"manifest_sha256,omitempty"`
	BindingSHA256        string `json:"binding_sha256,omitempty"`
	Plan                 string `json:"plan,omitempty"`
	BusinessExpiresAt    string `json:"business_expires_at,omitempty"`
	ServerTime           string `json:"server_time"`
}

type V2LogoutRequest struct {
	Product string `json:"product"`
}

type v2ErrorResponse struct {
	OK         bool   `json:"ok"`
	Message    string `json:"message"`
	ServerTime string `json:"server_time"`
}

func accountEmail(username string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(username))
	if !accountUsernamePattern.MatchString(normalized) {
		return "", fmt.Errorf("invalid username")
	}
	return normalized + "@accounts.license.invalid", nil
}

func decodeV2JSON(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxV2RequestBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid request body: multiple JSON values")
		}
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

func (s *Server) keygenConfigured() bool {
	return strings.TrimSpace(s.config.KeygenBaseURL) != "" &&
		strings.TrimSpace(s.config.KeygenAccountID) != "" &&
		strings.TrimSpace(s.config.KeygenProductID) != "" &&
		strings.TrimSpace(s.config.KeygenPublicKey) != ""
}

func (s *Server) handleV2Login(w http.ResponseWriter, r *http.Request) {
	if !s.keygenConfigured() || s.keygen == nil {
		writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeV2Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	defer r.Body.Close()
	var req V2LoginRequest
	if err := decodeV2JSON(w, r, &req); err != nil {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.Product) != s.expectedProductCode() || len(req.ClientVersion) > 64 || req.Password == "" || len(req.Password) > 256 {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	email, err := accountEmail(req.Username)
	if err != nil {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	clientIP := requestClientIP(r)
	rates := s.v2RateLimits()
	unlockLogin := rates.LockLogin(clientIP, email)
	defer unlockLogin()
	now := time.Now().UTC()
	if retryAfter := rates.LoginRetryAfter(clientIP, email, now); retryAfter > 0 {
		writeV2RateLimited(w, retryAfter)
		return
	}
	if !rates.AllowLogin(clientIP, email, now) {
		writeV2RateLimited(w, 5*time.Minute)
		return
	}
	session, err := s.keygen.Login(r.Context(), email, req.Password)
	if err != nil {
		var upstream *KeygenUpstreamError
		switch {
		case errors.As(err, &upstream) && upstream.StatusCode == http.StatusUnauthorized:
			rates.RecordLoginFailure(clientIP, email, time.Now().UTC())
			writeV2Error(w, http.StatusUnauthorized, "invalid credentials")
		case errors.As(err, &upstream) && upstream.StatusCode == http.StatusForbidden:
			rates.RecordLoginFailure(clientIP, email, time.Now().UTC())
			writeV2Error(w, http.StatusForbidden, "account unavailable")
		default:
			writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		}
		return
	}
	if session.Token == "" || session.UserID == "" {
		if session.Token != "" {
			_ = s.keygen.RevokeToken(r.Context(), session.Token)
		}
		writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		return
	}
	currentUser, err := s.keygen.CurrentUser(r.Context(), session.Token)
	if err != nil {
		_ = s.keygen.RevokeToken(r.Context(), session.Token)
		if isAuthenticationFailure(err) {
			rates.RecordLoginFailure(clientIP, email, time.Now().UTC())
		}
		writeV2UpstreamError(w, err, "account unavailable")
		return
	}
	if currentUser.ID != session.UserID || currentUser.Status != "ACTIVE" {
		_ = s.keygen.RevokeToken(r.Context(), session.Token)
		rates.RecordLoginFailure(clientIP, email, time.Now().UTC())
		writeV2Error(w, http.StatusForbidden, "account unavailable")
		return
	}
	rates.ResetLoginFailures(clientIP, email)
	normalizedUsername := strings.TrimSuffix(email, "@accounts.license.invalid")
	writeV2JSON(w, http.StatusOK, V2LoginResponse{
		OK:           true,
		Message:      "ok",
		SessionToken: session.Token,
		UserID:       session.UserID,
		Username:     normalizedUsername,
		ServerTime:   nowText(),
	})
}

func (s *Server) handleV2Activate(w http.ResponseWriter, r *http.Request) {
	if !s.keygenConfigured() || s.keygen == nil {
		writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeV2Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, err := requestBearerToken(r)
	if err != nil {
		writeV2Error(w, http.StatusUnauthorized, "authentication required")
		return
	}
	clientIP := requestClientIP(r)
	if !s.v2RateLimits().AllowActionIP(clientIP, "activate", time.Now().UTC()) {
		writeV2RateLimited(w, 10*time.Minute)
		return
	}
	defer r.Body.Close()
	var req V2ActivateRequest
	if err := decodeV2JSON(w, r, &req); err != nil {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.CardKey = strings.ToUpper(strings.TrimSpace(req.CardKey))
	if strings.TrimSpace(req.Product) != s.expectedProductCode() || len(req.ClientVersion) > 64 || req.DeviceFingerprint == "" || !validDeviceBinding(req.DeviceFingerprint, req.Components) || (req.CardKey != "" && !paidCardPattern.MatchString(req.CardKey)) {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	currentUser, err := s.keygen.CurrentUser(r.Context(), token)
	if err != nil {
		writeV2UpstreamError(w, err, "account unavailable")
		return
	}
	if !s.v2RateLimits().AllowAuthenticatedAction(token, "activate", time.Now().UTC()) {
		writeV2RateLimited(w, 10*time.Minute)
		return
	}
	if !keygenIDPattern.MatchString(currentUser.ID) || currentUser.Status != "ACTIVE" {
		writeV2Error(w, http.StatusForbidden, "account unavailable")
		return
	}
	binding := DeviceBinding{
		Fingerprint: req.DeviceFingerprint,
		Components:  req.Components,
	}
	resolution, err := s.keygen.ResolveLicense(r.Context(), token, s.config.KeygenProductID, req.CardKey, binding)
	if err != nil {
		writeV2UpstreamError(w, err, "license unavailable")
		return
	}
	license := resolution.License
	validationCardKey := req.CardKey
	if req.CardKey == "" && license.Plan != "TRIAL" {
		if resolution.Machine == nil {
			writeV2Error(w, http.StatusForbidden, "license unavailable")
			return
		}
		validationCardKey = license.Key
	}
	_, ok := validActivatableLicense(license, validationCardKey, s.config.KeygenProductID, time.Now().UTC(), false)
	if license.OwnerID != currentUser.ID {
		ok = false
	}
	if !ok {
		writeV2Error(w, http.StatusForbidden, "license unavailable")
		return
	}
	var machine KeygenMachine
	machineCreated := false
	if resolution.Machine != nil {
		machine = *resolution.Machine
	} else {
		machine, err = s.keygen.EnsureMachine(r.Context(), token, license, binding)
		if err != nil {
			var upstream *KeygenUpstreamError
			if errors.As(err, &upstream) && (upstream.StatusCode == http.StatusConflict || upstream.StatusCode == http.StatusUnprocessableEntity) {
				writeV2Error(w, http.StatusConflict, "device unavailable")
				return
			}
			writeV2UpstreamError(w, err, "device unavailable")
			return
		}
		machineCreated = true
	}
	if !keygenIDPattern.MatchString(machine.ID) || !keygenSHA256Pattern.MatchString(machine.Fingerprint) || machine.LicenseID != license.ID || machine.OwnerID != license.OwnerID || !matchesPhysicalMajority(machine.Components, binding.Components) {
		writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		return
	}
	refreshedLicense, err := s.keygen.GetLicense(r.Context(), token, license.ID)
	if err != nil {
		writeV2UpstreamError(w, err, "license unavailable")
		return
	}
	refreshedValidationCardKey := req.CardKey
	if req.CardKey == "" && refreshedLicense.Plan != "TRIAL" {
		refreshedValidationCardKey = refreshedLicense.Key
	}
	if machineCreated && refreshedLicense.Plan != "FOREVER" && refreshedLicense.ExpiresAt.IsZero() && refreshedLicense.BusinessExpiresAt.IsZero() {
		for _, delay := range [...]time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond} {
			if _, validWithoutExpiry := validActivatableLicense(refreshedLicense, refreshedValidationCardKey, s.config.KeygenProductID, time.Now().UTC(), false); !validWithoutExpiry {
				break
			}
			if err := waitForV2Retry(r.Context(), delay); err != nil {
				writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
				return
			}
			refreshedLicense, err = s.keygen.GetLicense(r.Context(), token, license.ID)
			if err != nil {
				writeV2UpstreamError(w, err, "license unavailable")
				return
			}
			refreshedValidationCardKey = req.CardKey
			if req.CardKey == "" && refreshedLicense.Plan != "TRIAL" {
				refreshedValidationCardKey = refreshedLicense.Key
			}
			if !refreshedLicense.ExpiresAt.IsZero() || !refreshedLicense.BusinessExpiresAt.IsZero() {
				break
			}
		}
	}
	checkNow := time.Now().UTC()
	expiresAt, ok := validActivatableLicense(refreshedLicense, refreshedValidationCardKey, s.config.KeygenProductID, checkNow, true)
	ownerMatches := refreshedLicense.OwnerID == currentUser.ID
	idMatches := refreshedLicense.ID == license.ID
	if !ok || !ownerMatches || !idMatches {
		log.Printf("Keygen V2 activation post-check rejected: valid=%t owner_match=%t id_match=%t status=%q plan=%q price=%d product_match=%t expiry_zero=%t expiry_future=%t business_expiry_zero=%t",
			ok, ownerMatches, idMatches, refreshedLicense.Status, refreshedLicense.Plan, refreshedLicense.Price,
			refreshedLicense.ProductID == s.config.KeygenProductID, refreshedLicense.ExpiresAt.IsZero(), refreshedLicense.ExpiresAt.After(checkNow), refreshedLicense.BusinessExpiresAt.IsZero())
		writeV2Error(w, http.StatusForbidden, "license unavailable")
		return
	}
	license = refreshedLicense
	expiresText := ""
	if !expiresAt.IsZero() {
		expiresText = expiresAt.UTC().Format(time.RFC3339)
	}
	writeV2JSON(w, http.StatusOK, V2ActivateResponse{
		OK:                 true,
		Message:            "ok",
		UserID:             license.OwnerID,
		LicenseID:          license.ID,
		MachineID:          machine.ID,
		MachineFingerprint: machine.Fingerprint,
		Plan:               license.Plan,
		Price:              license.Price,
		ExpiresAt:          expiresText,
		ServerTime:         nowText(),
	})
}

func (s *Server) handleV2Lease(w http.ResponseWriter, r *http.Request) {
	if !s.keygenConfigured() || s.keygen == nil {
		writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeV2Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, err := requestBearerToken(r)
	if err != nil {
		writeV2Error(w, http.StatusUnauthorized, "authentication required")
		return
	}
	clientIP := requestClientIP(r)
	if !s.v2RateLimits().AllowActionIP(clientIP, "lease", time.Now().UTC()) {
		writeV2RateLimited(w, 10*time.Minute)
		return
	}
	defer r.Body.Close()
	var req V2LeaseRequest
	if err := decodeV2JSON(w, r, &req); err != nil {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.Product) != s.expectedProductCode() || !keygenIDPattern.MatchString(req.MachineID) || !validDeviceBinding(req.DeviceFingerprint, req.Components) || !keygenSHA256Pattern.MatchString(req.ManifestSHA256) || !leaseChallengePattern.MatchString(req.Challenge) || len(req.ClientVersion) > 64 {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	currentUser, err := s.keygen.CurrentUser(r.Context(), token)
	if err != nil {
		writeV2UpstreamError(w, err, "lease unavailable")
		return
	}
	if !s.v2RateLimits().AllowAuthenticatedAction(token, "lease", time.Now().UTC()) {
		writeV2RateLimited(w, 10*time.Minute)
		return
	}
	machine, err := s.keygen.GetMachine(r.Context(), token, req.MachineID)
	if err != nil {
		writeV2UpstreamError(w, err, "lease unavailable")
		return
	}
	if currentUser.Status != "ACTIVE" || machine.ID != req.MachineID || machine.OwnerID != currentUser.ID || !matchesPhysicalMajority(machine.Components, req.Components) {
		writeV2Error(w, http.StatusForbidden, "lease unavailable")
		return
	}
	license, err := s.keygen.GetLicense(r.Context(), token, machine.LicenseID)
	if err != nil {
		writeV2UpstreamError(w, err, "lease unavailable")
		return
	}
	cardKey := license.Key
	if license.Plan == "TRIAL" {
		cardKey = ""
	}
	businessExpiresAt, ok := validActivatableLicense(license, cardKey, s.config.KeygenProductID, time.Now().UTC(), true)
	if !ok || license.ID != machine.LicenseID || license.OwnerID != currentUser.ID {
		writeV2Error(w, http.StatusForbidden, "lease unavailable")
		return
	}
	if !s.v2RateLimits().AllowAuthenticatedAction(token, "heartbeat", time.Now().UTC()) {
		writeV2RateLimited(w, 10*time.Minute)
		return
	}
	if !s.v2RateLimits().AllowAuthenticatedAction(token, "checkout", time.Now().UTC()) {
		writeV2RateLimited(w, 10*time.Minute)
		return
	}
	if !s.v2RateLimits().leaseChallenges.Use(req.Challenge, time.Now().UTC()) {
		writeV2Error(w, http.StatusConflict, "lease challenge already used")
		return
	}
	if err := s.keygen.Heartbeat(r.Context(), token, req.MachineID); err != nil {
		writeV2UpstreamError(w, err, "lease unavailable")
		return
	}
	machineFile, err := s.keygen.Checkout(r.Context(), token, req.MachineID, keygenCheckoutTTLSeconds)
	if err != nil {
		writeV2UpstreamError(w, err, "lease unavailable")
		return
	}
	if !validMachineFileLease(machineFile, time.Now().UTC()) {
		writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		return
	}
	businessExpiresText := ""
	if !businessExpiresAt.IsZero() {
		businessExpiresText = businessExpiresAt.UTC().Format(time.RFC3339)
	}
	writeV2JSON(w, http.StatusOK, V2LeaseResponse{
		OK:                   true,
		Message:              "ok",
		MachineFile:          machineFile.Certificate,
		MachineFileExpiresAt: machineFile.ExpiresAt.UTC().Format(time.RFC3339),
		RefreshAfterSeconds:  600,
		Challenge:            req.Challenge,
		ManifestSHA256:       req.ManifestSHA256,
		BindingSHA256:        leaseBindingSHA256(machineFile.Certificate, req.ManifestSHA256, req.Challenge),
		Plan:                 license.Plan,
		BusinessExpiresAt:    businessExpiresText,
		ServerTime:           nowText(),
	})
}

func (s *Server) handleV2Logout(w http.ResponseWriter, r *http.Request) {
	if !s.keygenConfigured() || s.keygen == nil {
		writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeV2Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, err := requestBearerToken(r)
	if err != nil {
		writeV2Error(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.v2RateLimits().AllowActionIP(requestClientIP(r), "logout", time.Now().UTC()) {
		writeV2RateLimited(w, 10*time.Minute)
		return
	}
	defer r.Body.Close()
	var req V2LogoutRequest
	if err := decodeV2JSON(w, r, &req); err != nil || strings.TrimSpace(req.Product) != s.expectedProductCode() {
		writeV2Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.keygen.RevokeToken(r.Context(), token); err != nil && !isAlreadyRevokedError(err) {
		writeV2UpstreamError(w, err, "logout failed")
		return
	}
	writeV2JSON(w, http.StatusOK, v2ErrorResponse{OK: true, Message: "ok", ServerTime: nowText()})
}

func writeV2Error(w http.ResponseWriter, status int, message string) {
	writeV2JSON(w, status, v2ErrorResponse{
		OK:         false,
		Message:    message,
		ServerTime: nowText(),
	})
}

func writeV2JSON(w http.ResponseWriter, status int, response any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func writeV2RateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int((retryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
	writeV2Error(w, http.StatusTooManyRequests, "too many requests")
}

func isAuthenticationFailure(err error) bool {
	var upstream *KeygenUpstreamError
	return errors.As(err, &upstream) &&
		(upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden)
}

func leaseBindingSHA256(machineFile, manifestSHA256, challenge string) string {
	payload := "LICENSE-AUTH-LEASE-V1\x00" + machineFile + "\x00" + manifestSHA256 + "\x00" + challenge
	digest := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("%X", digest[:])
}

func requestBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if len(header) < 8 || !strings.EqualFold(header[:7], "Bearer ") {
		return "", fmt.Errorf("invalid authorization")
	}
	token := header[7:]
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("invalid authorization")
	}
	return token, nil
}

func validPhysicalComponents(components map[string]string) bool {
	physicalCount := 0
	physicalFingerprints := make(map[string]struct{}, len(components))
	for name, fingerprint := range components {
		if _, ok := allowedDeviceComponents[name]; !ok || !keygenSHA256Pattern.MatchString(fingerprint) {
			return false
		}
		if name == "device_key" {
			continue
		}
		if _, duplicate := physicalFingerprints[fingerprint]; duplicate {
			return false
		}
		physicalFingerprints[fingerprint] = struct{}{}
		physicalCount++
	}
	return physicalCount >= 3
}

func matchesPhysicalMajority(bound, candidate map[string]string) bool {
	if !validPhysicalComponents(bound) || !validPhysicalComponents(candidate) {
		return false
	}
	boundPhysicalCount := 0
	matches := 0
	for name, fingerprint := range bound {
		if name == "device_key" {
			continue
		}
		boundPhysicalCount++
		if candidate[name] == fingerprint {
			matches++
		}
	}
	return matches >= boundPhysicalCount/2+1
}

func waitForV2Retry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validDeviceBinding(fingerprint string, components map[string]string) bool {
	return keygenSHA256Pattern.MatchString(fingerprint) &&
		len(components) <= len(allowedDeviceComponents) &&
		validPhysicalComponents(components)
}

func validActivatableLicense(license KeygenLicense, cardKey, productID string, now time.Time, requireExpiry bool) (time.Time, bool) {
	if !keygenIDPattern.MatchString(license.ID) || !keygenIDPattern.MatchString(license.OwnerID) || license.ProductID != productID || license.Status != "ACTIVE" {
		return time.Time{}, false
	}
	wantPrice, ok := map[string]int{"TRIAL": 0, "YEAR": 128, "FOREVER": 288}[license.Plan]
	if !ok || license.Price != wantPrice {
		return time.Time{}, false
	}
	if cardKey == "" && license.Plan != "TRIAL" || cardKey != "" && (license.Plan == "TRIAL" || license.Key != cardKey) {
		return time.Time{}, false
	}
	if !license.ExpiresAt.IsZero() && !now.Before(license.ExpiresAt) {
		return time.Time{}, false
	}
	effectiveExpiry := license.BusinessExpiresAt
	if effectiveExpiry.IsZero() {
		effectiveExpiry = license.ExpiresAt
	}
	if license.Plan != "FOREVER" && requireExpiry && effectiveExpiry.IsZero() {
		return time.Time{}, false
	}
	if !effectiveExpiry.IsZero() && !now.Before(effectiveExpiry) {
		return time.Time{}, false
	}
	return effectiveExpiry, true
}

func validMachineFileLease(file KeygenMachineFile, now time.Time) bool {
	if file.Certificate == "" || len(file.Certificate) > maxKeygenResponseBytes || file.Algorithm != "base64+ed25519" || file.TTL != keygenCheckoutTTLSeconds || file.IssuedAt.IsZero() || file.ExpiresAt.IsZero() {
		return false
	}
	if !file.ExpiresAt.After(now) || file.ExpiresAt.After(now.Add(3700*time.Second)) {
		return false
	}
	if file.IssuedAt.After(now.Add(time.Minute)) || file.IssuedAt.Before(now.Add(-5*time.Minute)) {
		return false
	}
	duration := file.ExpiresAt.Sub(file.IssuedAt)
	return duration > 0 && duration <= 3700*time.Second
}

func writeV2UpstreamError(w http.ResponseWriter, err error, unavailableMessage string) {
	if errors.Is(err, ErrKeygenAmbiguous) || errors.Is(err, ErrKeygenDeviceMismatch) {
		writeV2Error(w, http.StatusConflict, unavailableMessage)
		return
	}
	if errors.Is(err, ErrKeygenLicenseNotFound) {
		writeV2Error(w, http.StatusNotFound, unavailableMessage)
		return
	}
	var upstream *KeygenUpstreamError
	if errors.As(err, &upstream) {
		switch upstream.StatusCode {
		case http.StatusUnauthorized:
			writeV2Error(w, http.StatusUnauthorized, "authentication required")
			return
		case http.StatusForbidden:
			writeV2Error(w, http.StatusForbidden, unavailableMessage)
			return
		case http.StatusNotFound:
			writeV2Error(w, http.StatusNotFound, unavailableMessage)
			return
		}
	}
	writeV2Error(w, http.StatusServiceUnavailable, "authorization service unavailable")
}
