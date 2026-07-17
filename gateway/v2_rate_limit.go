package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	v2LoginAccountLimit   = 10
	v2LoginIPLimit        = 30
	v2ActionIPLimit       = 600
	v2ActionLimit         = 120
	v2RateMaxEntries      = 10000
	v2RateCleanupInterval = 256
)

type rateWindowEntry struct {
	started time.Time
	count   int
}

type fixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]rateWindowEntry
	ops     uint64
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]rateWindowEntry),
	}
}

func (l *fixedWindowLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ops++
	if l.ops%v2RateCleanupInterval == 0 {
		for entryKey, entry := range l.entries {
			if !now.Before(entry.started.Add(l.window)) {
				delete(l.entries, entryKey)
			}
		}
	}
	entry, exists := l.entries[key]
	if !exists {
		if len(l.entries) >= v2RateMaxEntries {
			return false
		}
		entry.started = now
	}
	if now.Before(entry.started) {
		now = entry.started
	}
	if !now.Before(entry.started.Add(l.window)) {
		entry = rateWindowEntry{started: now}
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}

type v2RateLimits struct {
	loginGate           loginAdmissionGate
	loginIP             *fixedWindowLimiter
	loginAccount        *fixedWindowLimiter
	loginFailures       *loginFailureBackoff
	action              *fixedWindowLimiter
	authenticatedAction *fixedWindowLimiter
	leaseChallenges     *singleUseChallengeGuard
}

func newV2RateLimits() *v2RateLimits {
	return &v2RateLimits{
		loginIP:             newFixedWindowLimiter(v2LoginIPLimit, 5*time.Minute),
		loginAccount:        newFixedWindowLimiter(v2LoginAccountLimit, 5*time.Minute),
		loginFailures:       newLoginFailureBackoff(),
		action:              newFixedWindowLimiter(v2ActionIPLimit, 10*time.Minute),
		authenticatedAction: newFixedWindowLimiter(v2ActionLimit, 10*time.Minute),
		leaseChallenges:     newSingleUseChallengeGuard(v2RateMaxEntries, time.Hour),
	}
}

func (s *Server) v2RateLimits() *v2RateLimits {
	s.v2RateOnce.Do(func() {
		s.v2Rates = newV2RateLimits()
	})
	return s.v2Rates
}

func (l *v2RateLimits) AllowLogin(ip, email string, now time.Time) bool {
	if !l.loginIP.Allow("ip:"+ip, now) {
		return false
	}
	return l.loginAccount.Allow("account:"+email, now)
}

func (l *v2RateLimits) LockLogin(ip, email string) func() {
	return l.loginGate.Lock(ip, email)
}

func (l *v2RateLimits) LoginRetryAfter(ip, email string, now time.Time) time.Duration {
	return l.loginFailures.RetryAfter(ip, email, now)
}

func (l *v2RateLimits) RecordLoginFailure(ip, email string, now time.Time) {
	l.loginFailures.RecordFailure(ip, email, now)
}

func (l *v2RateLimits) ResetLoginFailures(ip, email string) {
	l.loginFailures.Reset(ip, email)
}

func (l *v2RateLimits) AllowActionIP(ip, operation string, now time.Time) bool {
	return l.action.Allow(operation+":"+ip, now)
}

func (l *v2RateLimits) AllowAuthenticatedAction(token, operation string, now time.Time) bool {
	return l.authenticatedAction.Allow(actionRateKey(token, operation), now)
}

func actionRateKey(token, operation string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%s:%x", operation, digest[:16])
}

func requestClientIP(r *http.Request) string {
	remoteHost := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remoteHost); err == nil {
		remoteHost = host
	}
	remoteIP := net.ParseIP(strings.Trim(remoteHost, "[]"))
	if remoteIP != nil && remoteIP.IsLoopback() {
		if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); forwarded != nil {
			return forwarded.String()
		}
	}
	if remoteIP != nil {
		return remoteIP.String()
	}
	return "unknown"
}
