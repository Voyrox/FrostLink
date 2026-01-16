package proxy

import (
	"fmt"
	"sync"

	"golang.org/x/time/rate"
)

type RateLimitConfig struct {
	Enabled           bool
	RequestsPerSecond int
	Burst             int
}

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

const (
	defaultRPS   = 10
	defaultBurst = 20
)

var (
	instance *RateLimiter
	once     sync.Once
)

func GetRateLimiter() *RateLimiter {
	once.Do(func() {
		instance = &RateLimiter{
			limiters: make(map[string]*rate.Limiter),
		}
	})
	return instance
}

func (rl *RateLimiter) Allow(domain, ip string, cfg RateLimitConfig) bool {
	if !cfg.Enabled {
		return true
	}

	key := fmt.Sprintf("%s:%s", domain, ip)

	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		return limiter.Allow()
	}

	rps := cfg.RequestsPerSecond
	burst := cfg.Burst
	if rps <= 0 {
		rps = defaultRPS
	}
	if burst <= 0 {
		burst = defaultBurst
	}

	limiter = rate.NewLimiter(rate.Limit(rps), burst)

	rl.mu.Lock()
	rl.limiters[key] = limiter
	rl.mu.Unlock()

	return limiter.Allow()
}

func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	rl.limiters = make(map[string]*rate.Limiter)
	rl.mu.Unlock()
}
