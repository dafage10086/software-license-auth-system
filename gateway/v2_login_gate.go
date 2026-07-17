package main

import (
	"crypto/sha256"
	"sync"
)

const loginAdmissionShardCount = 256

type loginAdmissionGate struct {
	shards [loginAdmissionShardCount]sync.Mutex
}

func (g *loginAdmissionGate) Lock(ip, account string) func() {
	ipShard := loginAdmissionShard("ip:" + ip)
	accountShard := loginAdmissionShard("account:" + account)
	if accountShard < ipShard {
		ipShard, accountShard = accountShard, ipShard
	}
	g.shards[ipShard].Lock()
	if accountShard != ipShard {
		g.shards[accountShard].Lock()
	}
	return func() {
		if accountShard != ipShard {
			g.shards[accountShard].Unlock()
		}
		g.shards[ipShard].Unlock()
	}
}

func loginAdmissionShard(key string) int {
	digest := sha256.Sum256([]byte(key))
	return int(digest[0])
}
