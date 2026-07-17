package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFixedWindowLimiterRejectsAtLimitAndRecovers(t *testing.T) {
	limiter := newFixedWindowLimiter(2, time.Minute)
	now := time.Now().UTC()
	if !limiter.Allow("key", now) || !limiter.Allow("key", now.Add(time.Second)) {
		t.Fatal("limiter rejected requests below limit")
	}
	if limiter.Allow("key", now.Add(2*time.Second)) {
		t.Fatal("limiter accepted request over limit")
	}
	if !limiter.Allow("key", now.Add(time.Minute)) {
		t.Fatal("limiter did not recover after window")
	}
}

func TestFixedWindowLimiterDoesNotResetOnClockRollback(t *testing.T) {
	limiter := newFixedWindowLimiter(2, time.Minute)
	started := time.Date(2026, 7, 15, 6, 0, 0, 0, time.UTC)
	if !limiter.Allow("key", started) || !limiter.Allow("key", started.Add(time.Second)) {
		t.Fatal("limiter rejected requests below limit")
	}
	if limiter.Allow("key", started.Add(-time.Second)) {
		t.Fatal("clock rollback reset the active rate window")
	}
}

func TestActionRateKeyDoesNotContainBearer(t *testing.T) {
	token := "sensitive-user-bearer-token"
	key := actionRateKey(token, "lease")
	if strings.Contains(key, token) {
		t.Fatalf("rate key contains bearer: %q", key)
	}
}

func TestActionRateKeyIsStableAndBearerScoped(t *testing.T) {
	token := "same-user-bearer-token"
	first := actionRateKey(token, "lease")
	second := actionRateKey(token, "lease")
	if first != second {
		t.Fatalf("same bearer produced unstable rate keys: %q != %q", first, second)
	}
	if first == actionRateKey("another-user-bearer-token", "lease") {
		t.Fatal("different bearers produced the same rate key")
	}
	if first == actionRateKey(token, "activate") {
		t.Fatal("different operations produced the same rate key")
	}
}

func TestFixedWindowLimiterAtCapacityWaitsForPeriodicCleanup(t *testing.T) {
	limiter := newFixedWindowLimiter(1, time.Minute)
	now := time.Now().UTC()
	for i := 0; i < v2RateMaxEntries; i++ {
		limiter.entries[fmt.Sprintf("stale-%d", i)] = rateWindowEntry{
			started: now.Add(-2 * time.Minute),
			count:   1,
		}
	}

	if limiter.Allow("new-key", now) {
		t.Fatal("full limiter scanned and admitted a new key before periodic cleanup")
	}
	if len(limiter.entries) != v2RateMaxEntries {
		t.Fatalf("entry count = %d, want %d before periodic cleanup", len(limiter.entries), v2RateMaxEntries)
	}

	limiter.ops = 255
	if !limiter.Allow("new-key", now) {
		t.Fatal("periodic cleanup did not recover limiter capacity")
	}
}

func TestV2UnauthenticatedActionUsesSingleIPBucket(t *testing.T) {
	currentUserCalls := 0
	api := &fakeKeygenAPI{
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			currentUserCalls++
			return KeygenUser{}, &KeygenUpstreamError{StatusCode: http.StatusUnauthorized}
		},
	}
	s := newConfiguredV2TestServer(t, api)
	body := `{"product":"DEMO-PRODUCT","card_key":"YEAR-KEY","device_fingerprint":"` + strings.Repeat("D", 64) + `","components":{"bios":"` + strings.Repeat("A", 64) + `","smbios":"` + strings.Repeat("B", 64) + `","system_disk":"` + strings.Repeat("C", 64) + `"}}`
	for _, token := range []string{"fake-token-one", "fake-token-two"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v2/activate", strings.NewReader(body))
		req.RemoteAddr = "192.0.2.44:12345"
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		s.handleV2Activate(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
	}
	if currentUserCalls != 2 {
		t.Fatalf("CurrentUser calls = %d, want 2", currentUserCalls)
	}
	if got := len(s.v2RateLimits().action.entries); got != 1 {
		t.Fatalf("unauthenticated bearer values occupied %d action buckets, want one IP bucket", got)
	}
}

func TestV2ActionRateLimitUsesTenMinuteRetryAfter(t *testing.T) {
	s := newConfiguredV2TestServer(t, &fakeKeygenAPI{})
	s.v2RateLimits().action.limit = 0
	req := httptest.NewRequest(http.MethodPost, "/api/v2/logout", strings.NewReader(`{"product":"DEMO-PRODUCT"}`))
	req.RemoteAddr = "192.0.2.45:12345"
	req.Header.Set("Authorization", "Bearer user-token")
	rr := httptest.NewRecorder()

	s.handleV2Logout(rr, req)

	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "600" {
		t.Fatalf("status=%d retry-after=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}
}

func TestV2LoginRateLimitUsesFiveMinuteRetryAfter(t *testing.T) {
	s := newConfiguredV2TestServer(t, &fakeKeygenAPI{})
	s.v2RateLimits().loginIP.limit = 0
	req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"test-password"}`))
	req.RemoteAddr = "192.0.2.46:12345"
	rr := httptest.NewRecorder()

	s.handleV2Login(rr, req)

	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "300" {
		t.Fatalf("status=%d retry-after=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}
}

func TestV2LoginRateLimitStopsBeforeUpstream(t *testing.T) {
	calls := 0
	api := &fakeKeygenAPI{
		loginFn: func(context.Context, string, string) (KeygenSession, error) {
			calls++
			return KeygenSession{Token: "session-token", TokenID: "token-id", UserID: "user-id"}, nil
		},
		currentUserFn: func(context.Context, string) (KeygenUser, error) {
			return KeygenUser{ID: "user-id", Status: "ACTIVE"}, nil
		},
	}
	s := newConfiguredV2TestServer(t, api)
	for i := 0; i < v2LoginAccountLimit+1; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"test-password"}`))
		req.RemoteAddr = "192.0.2.10:12345"
		rr := httptest.NewRecorder()
		s.handleV2Login(rr, req)
		if i < v2LoginAccountLimit && rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d body=%s", i+1, rr.Code, rr.Body.String())
		}
		if i == v2LoginAccountLimit && rr.Code != http.StatusTooManyRequests {
			t.Fatalf("limited request status = %d body=%s", rr.Code, rr.Body.String())
		}
	}
	if calls != v2LoginAccountLimit {
		t.Fatalf("upstream calls = %d, want %d", calls, v2LoginAccountLimit)
	}
}

func TestV2LoginConsecutiveFailuresTriggerTemporaryBackoff(t *testing.T) {
	const threshold = 3
	calls := 0
	api := &fakeKeygenAPI{
		loginFn: func(context.Context, string, string) (KeygenSession, error) {
			calls++
			return KeygenSession{}, &KeygenUpstreamError{StatusCode: http.StatusUnauthorized}
		},
	}
	s := newConfiguredV2TestServer(t, api)
	for attempt := 1; attempt <= threshold+1; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"wrong-password"}`))
		req.RemoteAddr = "192.0.2.99:12345"
		rr := httptest.NewRecorder()
		s.handleV2Login(rr, req)
		if attempt <= threshold && rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d body=%s", attempt, rr.Code, rr.Body.String())
		}
		if attempt == threshold+1 {
			if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "15" {
				t.Fatalf("backoff status=%d retry-after=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
			}
		}
	}
	if calls != threshold {
		t.Fatalf("upstream calls=%d, want %d", calls, threshold)
	}
}

func TestLoginFailureBackoffExpiresAndResetClearsHistory(t *testing.T) {
	backoff := newLoginFailureBackoff()
	now := time.Date(2026, 7, 15, 6, 0, 0, 0, time.UTC)
	for i := 0; i < v2LoginBackoffThreshold; i++ {
		backoff.RecordFailure("192.0.2.1", "user1@accounts.license.invalid", now)
	}
	if got := backoff.RetryAfter("192.0.2.1", "user1@accounts.license.invalid", now); got != v2LoginBackoffDuration {
		t.Fatalf("retry after=%s, want %s", got, v2LoginBackoffDuration)
	}
	if got := backoff.RetryAfter("192.0.2.1", "user1@accounts.license.invalid", now.Add(v2LoginBackoffDuration)); got != 0 {
		t.Fatalf("backoff did not expire: %s", got)
	}

	backoff.Reset("192.0.2.1", "user1@accounts.license.invalid")
	backoff.RecordFailure("192.0.2.1", "user1@accounts.license.invalid", now.Add(time.Minute))
	if got := backoff.RetryAfter("192.0.2.1", "user1@accounts.license.invalid", now.Add(time.Minute)); got != 0 {
		t.Fatalf("reset did not clear failure history: %s", got)
	}
}

func TestV2ConcurrentLoginFailuresRespectBackoffThreshold(t *testing.T) {
	const attempts = 8
	var upstreamCalls atomic.Int32
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	api := &fakeKeygenAPI{
		loginFn: func(context.Context, string, string) (KeygenSession, error) {
			upstreamCalls.Add(1)
			current := inFlight.Add(1)
			for {
				maximum := maxInFlight.Load()
				if current <= maximum || maxInFlight.CompareAndSwap(maximum, current) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			return KeygenSession{}, &KeygenUpstreamError{StatusCode: http.StatusUnauthorized}
		},
	}
	s := newConfiguredV2TestServer(t, api)
	start := make(chan struct{})
	statuses := make(chan int, attempts)
	var waitGroup sync.WaitGroup
	for i := 0; i < attempts; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/api/v2/login", strings.NewReader(`{"product":"DEMO-PRODUCT","username":"user1","password":"wrong-password"}`))
			req.RemoteAddr = "192.0.2.100:12345"
			rr := httptest.NewRecorder()
			s.handleV2Login(rr, req)
			statuses <- rr.Code
		}()
	}
	close(start)
	waitGroup.Wait()
	close(statuses)

	unauthorized := 0
	rateLimited := 0
	for status := range statuses {
		switch status {
		case http.StatusUnauthorized:
			unauthorized++
		case http.StatusTooManyRequests:
			rateLimited++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if upstreamCalls.Load() != v2LoginBackoffThreshold || maxInFlight.Load() != 1 {
		t.Fatalf("upstream calls=%d max concurrent=%d", upstreamCalls.Load(), maxInFlight.Load())
	}
	if unauthorized != v2LoginBackoffThreshold || rateLimited != attempts-v2LoginBackoffThreshold {
		t.Fatalf("unauthorized=%d rate-limited=%d", unauthorized, rateLimited)
	}
}
