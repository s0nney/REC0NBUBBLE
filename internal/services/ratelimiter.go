package services

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu            sync.RWMutex
	attempts      map[string]int
	blockedUntil  map[string]time.Time
	failsLimit    int
	blockDuration time.Duration
}

func NewRateLimiter(failsLimit int, blockDuration time.Duration) *RateLimiter {
	return &RateLimiter{
		attempts:      make(map[string]int),
		blockedUntil:  make(map[string]time.Time),
		failsLimit:    failsLimit,
		blockDuration: blockDuration,
	}
}

func (rl *RateLimiter) RecordFailure(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.attempts[ip]++
	if rl.attempts[ip] >= rl.failsLimit {
		rl.blockedUntil[ip] = time.Now().Add(rl.blockDuration)
		return true
	}
	return false
}

func (rl *RateLimiter) IsBlocked(ip string) (bool, time.Duration) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if blockTime, exists := rl.blockedUntil[ip]; exists {
		if time.Now().Before(blockTime) {
			return true, time.Until(blockTime)
		}
		delete(rl.blockedUntil, ip)
		delete(rl.attempts, ip)
	}
	return false, 0
}

func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.attempts, ip)
	delete(rl.blockedUntil, ip)
}
