package core

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type rateLimitBucket struct {
	count     int
	resetTime time.Time
}

var (
	rateLimitMu    sync.Mutex
	rateLimitStore = make(map[string]*rateLimitBucket)
)

const (
	rateLimitCount  = 5
	rateLimitWindow = 1 * time.Minute
)

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !allowLoginRequest(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded, try again in 1 minute",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func allowLoginRequest(ip string) bool {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	now := time.Now()
	bucket, exists := rateLimitStore[ip]

	if !exists || now.After(bucket.resetTime) {
		rateLimitStore[ip] = &rateLimitBucket{
			count:     1,
			resetTime: now.Add(rateLimitWindow),
		}
		return true
	}

	if bucket.count >= rateLimitCount {
		return false
	}

	bucket.count++
	return true
}

func CheckLoginRateLimit(ip string) bool {
	return allowLoginRequest(ip)
}
