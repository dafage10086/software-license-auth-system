package main

import (
	"crypto/sha256"
	"sync"
	"time"
)

type singleUseChallengeGuard struct {
	mu         sync.Mutex
	max        int
	ttl        time.Duration
	entries    map[[sha256.Size]byte]time.Time
	operations uint64
}

func newSingleUseChallengeGuard(max int, ttl time.Duration) *singleUseChallengeGuard {
	return &singleUseChallengeGuard{
		max:     max,
		ttl:     ttl,
		entries: make(map[[sha256.Size]byte]time.Time),
	}
}

func (g *singleUseChallengeGuard) Use(challenge string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.operations++
	if g.operations%v2RateCleanupInterval == 0 {
		for digest, expiresAt := range g.entries {
			if !now.Before(expiresAt) {
				delete(g.entries, digest)
			}
		}
	}

	digest := sha256.Sum256([]byte(challenge))
	if expiresAt, exists := g.entries[digest]; exists && now.Before(expiresAt) {
		return false
	}
	delete(g.entries, digest)
	if len(g.entries) >= g.max {
		return false
	}
	g.entries[digest] = now.Add(g.ttl)
	return true
}
