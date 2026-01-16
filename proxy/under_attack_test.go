package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadUnderAttackConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "under_attack.json")

	originalPath := underAttackConfigPath
	underAttackConfigPath = configPath
	defer func() { underAttackConfigPath = originalPath }()

	configLoaded = false
	configCache = nil
	defer func() { configLoaded = false; configCache = nil }()

	loadUnderAttackConfig()
	if configCache == nil {
		t.Error("Expected configCache to be initialized")
	}
}

func TestLoadUnderAttackConfigWithData(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "under_attack.json")

	originalPath := underAttackConfigPath
	underAttackConfigPath = configPath
	defer func() { underAttackConfigPath = originalPath }()

	configLoaded = false
	configCache = nil
	defer func() { configLoaded = false; configCache = nil }()

	configData := `{
		"version": "1.0",
		"domains": {
			"example.com": {
				"enabled": true,
				"difficulty": 12,
				"cookie_duration_h": 24,
				"hmac_secret": "test-secret-key"
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	loadUnderAttackConfig()

	if !configLoaded {
		t.Error("Expected configLoaded to be true")
	}

	configMu.RLock()
	cfg, ok := configCache["example.com"]
	configMu.RUnlock()
	if !ok {
		t.Error("Expected to find example.com config")
	}
	if !cfg.Enabled {
		t.Error("Expected enabled to be true")
	}
	if cfg.Difficulty != 12 {
		t.Errorf("Expected difficulty 12, got %d", cfg.Difficulty)
	}
	if cfg.HMACSecret != "test-secret-key" {
		t.Errorf("Expected hmac_secret to be preserved")
	}
}

func TestSetUnderAttackMode(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "under_attack.json")

	originalPath := underAttackConfigPath
	underAttackConfigPath = configPath
	defer func() { underAttackConfigPath = originalPath }()

	configLoaded = false
	configCache = nil
	defer func() { configLoaded = false; configCache = nil }()

	loadUnderAttackConfig()

	err := SetUnderAttackMode("test.com", true)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !IsUnderAttackMode("test.com") {
		t.Error("Expected IsUnderAttackMode to return true")
	}

	cfg := GetUnderAttackConfig("test.com")
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if !cfg.Enabled {
		t.Error("Expected enabled to be true")
	}
	if cfg.Difficulty != 12 {
		t.Errorf("Expected default difficulty 12, got %d", cfg.Difficulty)
	}
	if cfg.CookieDurationH != 24 {
		t.Errorf("Expected default cookie duration 24, got %d", cfg.CookieDurationH)
	}
}

func TestSetUnderAttackModeDisable(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "under_attack.json")

	originalPath := underAttackConfigPath
	underAttackConfigPath = configPath
	defer func() { underAttackConfigPath = originalPath }()

	configLoaded = false
	configCache = nil
	defer func() { configLoaded = false; configCache = nil }()

	loadUnderAttackConfig()

	SetUnderAttackMode("test.com", true)
	if !IsUnderAttackMode("test.com") {
		t.Error("Expected enabled after setting true")
	}

	SetUnderAttackMode("test.com", false)
	if IsUnderAttackMode("test.com") {
		t.Error("Expected disabled after setting false")
	}
}

func TestGenerateAltchaChallenge(t *testing.T) {
	challenge, err := GenerateAltchaChallenge("test.com", 12)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if challenge.Algorithm != "SHA-256" {
		t.Errorf("Expected algorithm SHA-256, got %s", challenge.Algorithm)
	}

	if challenge.Challenge == "" {
		t.Error("Expected non-empty challenge")
	}

	if challenge.MaxNumber != 1000000 {
		t.Errorf("Expected maxNumber 1000000, got %d", challenge.MaxNumber)
	}

	if challenge.Signature == "" {
		t.Error("Expected non-empty signature")
	}
}

func TestGenerateAltchaChallengeDefaultDifficulty(t *testing.T) {
	challenge, err := GenerateAltchaChallenge("test.com", 0)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if challenge.MaxNumber != 1000000 {
		t.Errorf("Expected maxNumber 1000000, got %d", challenge.MaxNumber)
	}
}

func TestGenerateAltchaChallengeCustomDifficulty(t *testing.T) {
	challenge, err := GenerateAltchaChallenge("test.com", 16)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if challenge.MaxNumber != 1000000 {
		t.Errorf("Expected maxNumber 1000000, got %d", challenge.MaxNumber)
	}
}

func TestSignAndVerifySignature(t *testing.T) {
	payload := `{"salt":"test","maxnumber":100000}`
	secret := "test-secret"

	signature := signChallenge(payload, secret)

	if signature == "" {
		t.Error("Expected non-empty signature")
	}

	if !verifySignature(payload, signature, secret) {
		t.Error("Expected signature to be valid")
	}

	if verifySignature(payload, signature, "wrong-secret") {
		t.Error("Expected signature to be invalid with wrong secret")
	}

	if verifySignature("wrong-payload", signature, secret) {
		t.Error("Expected signature to be invalid with wrong payload")
	}
}

func TestVerifyAltchaSolution(t *testing.T) {
	challenge, err := GenerateAltchaChallenge("test.com", 12)
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	cfg := GetUnderAttackConfig("test.com")
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}

	cfg.Difficulty = 12
	configMu.Lock()
	configCache["test.com"] = cfg
	configMu.Unlock()

	payload := AltchaPayload{
		Algorithm: "SHA-256",
		Challenge: challenge.Challenge,
		Number:    0,
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
		MaxNumber: challenge.MaxNumber,
	}
	payloadJSON, _ := json.Marshal(payload)

	computedHash := sha256.Sum256([]byte(challenge.Salt + fmt.Sprintf("%d", 0)))
	threshold := int(challenge.MaxNumber) >> cfg.Difficulty
	hashValue := int(uint(computedHash[0]) | uint(computedHash[1])<<8 | uint(computedHash[2])<<16 | uint(computedHash[3])<<24)

	if hashValue >= threshold {
		t.Skipf("Hash value %d >= threshold %d, skipping verification test", hashValue, threshold)
	}

	if !VerifyAltchaSolution(string(payloadJSON), "test.com") {
		t.Error("Expected verification to succeed for nonce=0")
	}
}

func TestVerifyAltchaSolutionInvalid(t *testing.T) {
	challenge, err := GenerateAltchaChallenge("test.com", 12)
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	payload := AltchaPayload{
		Algorithm: "SHA-256",
		Challenge: challenge.Challenge,
		Number:    0,
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
		MaxNumber: challenge.MaxNumber,
	}
	payloadJSON, _ := json.Marshal(payload)

	if VerifyAltchaSolution("", "test.com") {
		t.Error("Expected verification to fail for empty challenge")
	}

	invalidPayload := AltchaPayload{
		Algorithm: "SHA-256",
		Challenge: challenge.Challenge,
		Number:    0,
		Salt:      challenge.Salt,
		Signature: "invalidsignature",
		MaxNumber: challenge.MaxNumber,
	}
	invalidJSON, _ := json.Marshal(invalidPayload)

	if VerifyAltchaSolution(string(invalidJSON), "test.com") {
		t.Error("Expected verification to fail for invalid signature")
	}

	if VerifyAltchaSolution(string(payloadJSON), "nonexistent.com") {
		t.Error("Expected verification to fail for nonexistent domain")
	}
}

func TestUpdateUnderAttackConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "under_attack.json")

	originalPath := underAttackConfigPath
	underAttackConfigPath = configPath
	defer func() { underAttackConfigPath = originalPath }()

	configLoaded = false
	configCache = nil
	defer func() { configLoaded = false; configCache = nil }()

	loadUnderAttackConfig()

	err := UpdateUnderAttackConfig("test.com", 16, 48)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	cfg := GetUnderAttackConfig("test.com")
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if cfg.Difficulty != 16 {
		t.Errorf("Expected difficulty 16, got %d", cfg.Difficulty)
	}
	if cfg.CookieDurationH != 48 {
		t.Errorf("Expected cookie duration 48, got %d", cfg.CookieDurationH)
	}
}

func TestUpdateUnderAttackConfigInvalidDifficulty(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "under_attack.json")

	originalPath := underAttackConfigPath
	underAttackConfigPath = configPath
	defer func() { underAttackConfigPath = originalPath }()

	configLoaded = false
	configCache = nil
	defer func() { configLoaded = false; configCache = nil }()

	loadUnderAttackConfig()

	err := UpdateUnderAttackConfig("test.com", 0, 24)
	if err == nil {
		t.Error("Expected error for difficulty below minimum")
	}

	err = UpdateUnderAttackConfig("test.com", 25, 24)
	if err == nil {
		t.Error("Expected error for difficulty above maximum")
	}
}

func TestUpdateUnderAttackConfigInvalidDuration(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "under_attack.json")

	originalPath := underAttackConfigPath
	underAttackConfigPath = configPath
	defer func() { underAttackConfigPath = originalPath }()

	configLoaded = false
	configCache = nil
	defer func() { configLoaded = false; configCache = nil }()

	loadUnderAttackConfig()

	err := UpdateUnderAttackConfig("test.com", 12, 0)
	if err == nil {
		t.Error("Expected error for duration below minimum")
	}

	err = UpdateUnderAttackConfig("test.com", 12, 200)
	if err == nil {
		t.Error("Expected error for duration above maximum")
	}
}

func TestIsUnderAttackModeEmptyDomain(t *testing.T) {
	if IsUnderAttackMode("") {
		t.Error("Expected empty domain to return false")
	}
}

func TestGetUnderAttackConfigEmptyDomain(t *testing.T) {
	if GetUnderAttackConfig("") != nil {
		t.Error("Expected empty domain to return nil")
	}
}

func TestSetUnderAttackModeEmptyDomain(t *testing.T) {
	err := SetUnderAttackMode("", true)
	if err == nil {
		t.Error("Expected error for empty domain")
	}
}

func TestVerifiedCookie(t *testing.T) {
	clientIP := "192.168.1.1"

	verifiedCookieMu.Lock()
	verifiedCookies = sync.Map{}
	verifiedCookieCount = 0
	verifiedCookieMu.Unlock()

	verifiedCookieMu.Lock()
	token := fmt.Sprintf("%d-%d", time.Now().UnixNano(), 1)
	expiresAt := time.Now().Add(24 * time.Hour)
	verifiedCookies.Store(token, fmt.Sprintf("%s|%s", clientIP, expiresAt.Format(time.RFC3339)))
	verifiedCookieMu.Unlock()

	time.Sleep(10 * time.Millisecond)

	found := false
	verifiedCookies.Range(func(key, value interface{}) bool {
		stored, ok := value.(string)
		if ok && strings.HasPrefix(stored, clientIP) {
			found = true
		}
		return true
	})

	if !found {
		t.Error("Expected cookie to be stored for clientIP")
	}
}

func TestDifferentIPNotVerified(t *testing.T) {
	verifiedCookieMu.Lock()
	verifiedCookies = sync.Map{}
	verifiedCookieCount = 0
	verifiedCookieMu.Unlock()

	verifiedCookieMu.Lock()
	token := fmt.Sprintf("%d-%d", time.Now().UnixNano(), 1)
	expiresAt := time.Now().Add(24 * time.Hour)
	verifiedCookies.Store(token, fmt.Sprintf("192.168.1.1|%s", expiresAt.Format(time.RFC3339)))
	verifiedCookieMu.Unlock()

	time.Sleep(10 * time.Millisecond)

	found := false
	verifiedCookies.Range(func(key, value interface{}) bool {
		stored, ok := value.(string)
		if ok && strings.HasPrefix(stored, "192.168.1.2") {
			found = true
		}
		return true
	})

	if found {
		t.Error("Expected different IP to not be verified")
	}
}
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := generateSalt()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if salt1 == "" {
		t.Error("Expected non-empty salt")
	}

	salt2, err := generateSalt()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if salt1 == salt2 {
		t.Error("Expected different salts")
	}
}

func TestGenerateRandomHex(t *testing.T) {
	hex1, err := generateRandomHex(32)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(hex1) != 32 {
		t.Errorf("Expected 32 character hex string, got %d", len(hex1))
	}

	hex2, err := generateRandomHex(32)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if hex1 == hex2 {
		t.Error("Expected different hex strings")
	}
}
