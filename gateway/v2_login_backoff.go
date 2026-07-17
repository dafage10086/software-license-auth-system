package main

import (
	"sync"
	"time"
)

const (
	v2LoginBackoffThreshold  = 3
	v2LoginBackoffDuration   = 15 * time.Second
	v2LoginFailureResetAfter = 10 * time.Minute
)

type loginFailureEntry struct {
	failures     int
	lastFailure  time.Time
	blockedUntil time.Time
}

type loginFailureBackoff struct {
	mu      sync.Mutex
	entries map[string]loginFailureEntry
	ops     uint64
}

func newLoginFailureBackoff() *loginFailureBackoff {
	return &loginFailureBackoff{entries: make(map[string]loginFailureEntry)}
}

func (b *loginFailureBackoff) RetryAfter(ip, account string, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	var retryAfter time.Duration
	for _, key := range loginFailureKeys(ip, account) {
		entry, exists := b.entries[key]
		if !exists {
			continue
		}
		if !now.Before(entry.lastFailure.Add(v2LoginFailureResetAfter)) {
			delete(b.entries, key)
			continue
		}
		if remaining := entry.blockedUntil.Sub(now); remaining > retryAfter {
			retryAfter = remaining
		}
	}
	return retryAfter
}

func (b *loginFailureBackoff) RecordFailure(ip, account string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.ops++
	if b.ops%v2RateCleanupInterval == 0 {
		for key, entry := range b.entries {
			if !now.Before(entry.lastFailure.Add(v2LoginFailureResetAfter)) {
				delete(b.entries, key)
			}
		}
	}
	for _, key := range loginFailureKeys(ip, account) {
		entry, exists := b.entries[key]
		if exists && !now.Before(entry.lastFailure.Add(v2LoginFailureResetAfter)) {
			entry = loginFailureEntry{}
			exists = false
		}
		if !exists && len(b.entries) >= v2RateMaxEntries {
			continue
		}
		entry.failures++
		entry.lastFailure = now
		if entry.failures >= v2LoginBackoffThreshold {
			entry.blockedUntil = now.Add(v2LoginBackoffDuration)
		}
		b.entries[key] = entry
	}
}

func (b *loginFailureBackoff) Reset(ip, account string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, key := range loginFailureKeys(ip, account) {
		delete(b.entries, key)
	}
}

func loginFailureKeys(ip, account string) [2]string {
	return [2]string{"ip:" + ip, "account:" + account}
}
