package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SparkProxy/ui"

	"github.com/gin-gonic/gin"
)

const defaultMetricsTokenFile = "./db/metrics_token"

var (
	metricsAuthToken     string
	metricsAuthTokenOnce sync.Once
	tokenLoaded          bool
)

func GetMetricsAuthToken() string {
	metricsAuthTokenOnce.Do(func() {
		tokenFromEnv := os.Getenv("METRICS_AUTH_TOKEN")
		tokenFromFile := loadMetricsTokenFromFile()

		if tokenFromEnv != "" {
			metricsAuthToken = tokenFromEnv
			ui.SystemLog("info", "metrics", "Using METRICS_AUTH_TOKEN from environment")
			tokenLoaded = true
		} else if tokenFromFile != "" {
			metricsAuthToken = tokenFromFile
			tokenLoaded = true
			ui.SystemLog("info", "metrics", fmt.Sprintf("Loaded metrics token from file (first 8 chars): %s...", metricsAuthToken[:8]))
		} else {
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err != nil {
				ui.SystemLog("error", "metrics", fmt.Sprintf("Failed to generate metrics token: %v", err))
				return
			}
			metricsAuthToken = hex.EncodeToString(b)
			ui.SystemLog("info", "metrics", fmt.Sprintf("Generated new metrics auth token (first 8 chars): %s...", metricsAuthToken[:8]))

			if err := saveMetricsTokenToFile(metricsAuthToken); err != nil {
				ui.SystemLog("error", "metrics", fmt.Sprintf("Failed to save metrics token: %v", err))
			}
		}
	})
	return metricsAuthToken
}

func loadMetricsTokenFromFile() string {
	path := metricsTokenFilePath()
	if path == "" {
		return ""
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		ui.SystemLog("error", "metrics", fmt.Sprintf("Failed to read metrics token file: %v", err))
		return ""
	}

	token := strings.TrimSpace(string(data))
	return token
}

func saveMetricsTokenToFile(token string) error {
	path := metricsTokenFilePath()
	if path == "" {
		path = defaultMetricsTokenFile
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create metrics token directory: %w", err)
	}

	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write metrics token file: %w", err)
	}

	ui.SystemLog("info", "metrics", fmt.Sprintf("Saved metrics token to %s", path))
	return nil
}

func metricsTokenFilePath() string {
	return os.Getenv("METRICS_TOKEN_FILE")
}

func MetricsAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := GetMetricsAuthToken()
		if token == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "metrics not configured"})
			c.Abort()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Header("WWW-Authenticate", `Bearer realm="metrics"`)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			c.Abort()
			return
		}

		providedToken := strings.TrimPrefix(authHeader, "Bearer ")
		if providedToken != token {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func StartUptimeUpdater() {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		start := time.Now()
		for range ticker.C {
			SetUptime(time.Since(start).Seconds())
		}
	}()
}
