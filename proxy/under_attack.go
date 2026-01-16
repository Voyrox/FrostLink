package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SparkProxy/ui"
)

const underAttackConfigPathDefault = "./db/under_attack.json"

var underAttackConfigPath = underAttackConfigPathDefault

type UnderAttackConfig struct {
	Enabled         bool      `json:"enabled"`
	Difficulty      int       `json:"difficulty"`
	CookieDurationH int       `json:"cookie_duration_h"`
	HMACSecret      string    `json:"hmac_secret"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type AltchaChallenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int64  `json:"maxNumber"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

type AltchaPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int64  `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
	MaxNumber int64  `json:"maxNumber"`
}

type AltchaVerification struct {
	Payload string `json:"payload"`
}

type AltchaVerificationResponse struct {
	Verified bool   `json:"verified"`
	Redirect string `json:"redirect,omitempty"`
}

type altchaFile struct {
	Version string                        `json:"version"`
	Domains map[string]*UnderAttackConfig `json:"domains"`
}

type AltchaDecodedPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int64  `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
	MaxNumber int64  `json:"maxNumber,omitempty"`
	Tool      int    `json:"tool,omitempty"`
}

var (
	configMu     sync.RWMutex
	configCache  map[string]*UnderAttackConfig
	configLoaded bool

	verifiedCookies     sync.Map
	verifiedCookieMu    sync.Mutex
	verifiedCookieCount int64

	altchaTpl     *template.Template
	altchaTplOnce sync.Once
)

func loadAltchaTemplate() {
	altchaTplOnce.Do(func() {
		var err error
		tpls, err := template.ParseGlob("./views/*.tmpl")
		if err != nil {
			ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to parse templates: %v", err))
			return
		}
		altchaTpl = tpls.Lookup("challenge")
		if altchaTpl == nil {
			ui.SystemLog("error", "altcha", "Template 'challenge' not found in ./views/")
		}
	})
}

func loadUnderAttackConfig() {
	configMu.Lock()
	defer configMu.Unlock()

	if configLoaded {
		return
	}

	data, err := os.ReadFile(underAttackConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
		}
		configCache = make(map[string]*UnderAttackConfig)
		configLoaded = true
		return
	}

	var af altchaFile
	if err := json.Unmarshal(data, &af); err != nil {
		configCache = make(map[string]*UnderAttackConfig)
		configLoaded = true
		return
	}

	if af.Domains == nil {
		af.Domains = make(map[string]*UnderAttackConfig)
	}

	configCache = af.Domains
	configLoaded = true
}

func saveUnderAttackConfig() {
	configMu.RLock()
	af := altchaFile{
		Version: "1.0",
		Domains: make(map[string]*UnderAttackConfig),
	}
	for domain, cfg := range configCache {
		if domain == "" {
			continue
		}
		af.Domains[domain] = cfg
	}
	configMu.RUnlock()

	data, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to marshal config: %v", err))
		return
	}

	if err := os.MkdirAll(filepath.Dir(underAttackConfigPath), 0755); err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to create config dir: %v", err))
		return
	}

	if err := os.WriteFile(underAttackConfigPath, data, 0600); err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to write config: %v", err))
	}
}

func IsUnderAttackMode(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	loadUnderAttackConfig()
	configMu.RLock()
	defer configMu.RUnlock()

	cfg, ok := configCache[domain]
	return ok && cfg.Enabled
}

func GetUnderAttackConfig(domain string) *UnderAttackConfig {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	loadUnderAttackConfig()
	configMu.RLock()
	defer configMu.RUnlock()

	cfg, ok := configCache[domain]
	if !ok {
		return nil
	}

	clone := *cfg
	return &clone
}

func getOrCreateHMACSecret(domain string) string {
	loadUnderAttackConfig()
	configMu.Lock()
	defer configMu.Unlock()

	cfg, ok := configCache[domain]
	if !ok {
		cfg = &UnderAttackConfig{
			Difficulty:      12,
			CookieDurationH: 24,
		}
		configCache[domain] = cfg
	}

	if cfg.HMACSecret == "" {
		secret, err := generateRandomHex(32)
		if err != nil {
			ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to generate HMAC secret: %v", err))
			return ""
		}
		cfg.HMACSecret = secret
		cfg.UpdatedAt = time.Now()
		go saveUnderAttackConfig()
	}

	return cfg.HMACSecret
}

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateSalt() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func signChallenge(payload, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func verifySignature(payload, signature, secret string) bool {
	expected := signChallenge(payload, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}

func GenerateAltchaChallenge(domain string, difficulty int) (*AltchaChallenge, error) {
	const defaultMaxNumber int64 = 1000000

	maxNumber := defaultMaxNumber

	saltBytes := make([]byte, 12)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	saltHex := hex.EncodeToString(saltBytes)

	number, err := rand.Int(rand.Reader, big.NewInt(maxNumber+1))
	if err != nil {
		return nil, fmt.Errorf("failed to generate number: %w", err)
	}
	numberInt64 := number.Int64()

	challengeData := saltHex + fmt.Sprintf("%d", numberInt64)
	challengeHash := sha256.Sum256([]byte(challengeData))
	challengeHex := hex.EncodeToString(challengeHash[:])

	secret := getOrCreateHMACSecret(domain)

	signature := signChallenge(challengeHex, secret)

	return &AltchaChallenge{
		Algorithm: "SHA-256",
		Challenge: challengeHex,
		MaxNumber: maxNumber,
		Salt:      saltHex,
		Signature: signature,
	}, nil
}

func VerifyAltchaSolution(payloadJSON string, domain string) bool {
	if payloadJSON == "" {
		return false
	}

	loadUnderAttackConfig()
	configMu.RLock()
	_, ok := configCache[domain]
	configMu.RUnlock()
	if !ok {
		return false
	}

	var payload AltchaPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return false
	}

	secret := getOrCreateHMACSecret(domain)

	hmacSig := hmac.New(sha256.New, []byte(secret))
	hmacSig.Write([]byte(payload.Challenge))
	expectedSig := hex.EncodeToString(hmacSig.Sum(nil))

	if !hmac.Equal([]byte(payload.Signature), []byte(expectedSig)) {
		return false
	}

	saltRaw := payload.Salt

	number := payload.Number
	challengeData := saltRaw + fmt.Sprintf("%d", number)
	challengeHash := sha256.Sum256([]byte(challengeData))
	computedChallenge := hex.EncodeToString(challengeHash[:])

	if computedChallenge != payload.Challenge {
		return false
	}

	return true
}

func SetUnderAttackMode(domain string, enabled bool) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	loadUnderAttackConfig()
	configMu.Lock()
	defer configMu.Unlock()

	cfg, ok := configCache[domain]
	if !ok {
		cfg = &UnderAttackConfig{
			Difficulty:      12,
			CookieDurationH: 24,
		}
		configCache[domain] = cfg
	}

	cfg.Enabled = enabled
	cfg.UpdatedAt = time.Now()
	go saveUnderAttackConfig()

	ui.SystemLog("info", "altcha", fmt.Sprintf("Under Attack Mode %s for %s", map[bool]string{true: "enabled", false: "disabled"}[enabled], domain))
	return nil
}

func UpdateUnderAttackConfig(domain string, difficulty, cookieDurationH int) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if difficulty < 1 || difficulty > 20 {
		return fmt.Errorf("difficulty must be between 1 and 20")
	}
	if cookieDurationH < 1 || cookieDurationH > 168 {
		return fmt.Errorf("cookie duration must be between 1 and 168 hours")
	}

	loadUnderAttackConfig()
	configMu.Lock()
	defer configMu.Unlock()

	cfg, ok := configCache[domain]
	if !ok {
		cfg = &UnderAttackConfig{
			Enabled:         false,
			Difficulty:      difficulty,
			CookieDurationH: cookieDurationH,
		}
		configCache[domain] = cfg
	} else {
		cfg.Difficulty = difficulty
		cfg.CookieDurationH = cookieDurationH
	}
	cfg.UpdatedAt = time.Now()

	go saveUnderAttackConfig()
	return nil
}

func cleanupVerifiedCookies() {
	for {
		time.Sleep(5 * time.Minute)

		now := time.Now()
		verifiedCookies.Range(func(key, value interface{}) bool {
			stored, ok := value.(string)
			if !ok {
				verifiedCookies.Delete(key)
				return true
			}

			parts := strings.Split(stored, "|")
			if len(parts) < 2 {
				verifiedCookies.Delete(key)
				return true
			}

			expiresAt, err := time.Parse(time.RFC3339, parts[1])
			if err != nil || now.After(expiresAt) {
				verifiedCookies.Delete(key)
			}
			return true
		})
	}
}

func SetVerifiedCookie(w http.ResponseWriter, clientIP string) {
	if clientIP == "" || w == nil {
		return
	}

	verifiedCookieMu.Lock()
	defer verifiedCookieMu.Unlock()

	verifiedCookieCount++
	token := fmt.Sprintf("%d-%d", time.Now().UnixNano(), verifiedCookieCount)
	expiresAt := time.Now().Add(24 * time.Hour)
	verifiedCookies.Store(token, fmt.Sprintf("%s|%s", clientIP, expiresAt.Format(time.RFC3339)))

	cookieValue := fmt.Sprintf("%s|%d", token, verifiedCookieCount)
	http.SetCookie(w, &http.Cookie{
		Name:     "sp_challenge",
		Value:    cookieValue,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

func IsVerified(r *http.Request) bool {
	clientIP := r.RemoteAddr
	if i := strings.IndexByte(clientIP, ':'); i > -1 {
		clientIP = clientIP[:i]
	}

	if clientIP == "" {
		return false
	}

	cookie, err := r.Cookie("sp_challenge")
	if err != nil {
		return false
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) < 2 {
		return false
	}

	token := parts[0]

	verifiedCookieMu.Lock()
	defer verifiedCookieMu.Unlock()

	now := time.Now()
	var storedValue interface{}
	found := false
	verifiedCookies.Range(func(key, value interface{}) bool {
		if key.(string) == token {
			storedValue = value
			found = true
			return false
		}
		return true
	})

	if !found {
		return false
	}

	stored, ok := storedValue.(string)
	if !ok {
		return false
	}

	storedParts := strings.Split(stored, "|")
	if len(storedParts) < 2 {
		return false
	}

	storedIP := storedParts[0]
	expiresStr := storedParts[1]
	expiresAt, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		return false
	}

	if now.After(expiresAt) {
		verifiedCookies.Delete(token)
		return false
	}

	return storedIP == clientIP
}

func ServeAltchaPage(w http.ResponseWriter, r *http.Request, domain, redirectURL string) {
	if redirectURL == "" {
		redirectURL = r.URL.Query().Get("redirect")
	}
	if redirectURL == "" {
		redirectURL = r.Header.Get("Referer")
	}
	if redirectURL == "" {
		redirectURL = "/"
	}

	clientIP := r.RemoteAddr
	if i := strings.IndexByte(clientIP, ':'); i > -1 {
		clientIP = clientIP[:i]
	}

	cfg := GetUnderAttackConfig(domain)
	if cfg == nil {
		cfg = &UnderAttackConfig{
			Difficulty:      12,
			CookieDurationH: 24,
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	loadAltchaTemplate()

	if altchaTpl == nil {
		http.Error(w, "Template not available", http.StatusInternalServerError)
		return
	}

	data := struct {
		Domain      string
		Difficulty  int
		RedirectURL string
	}{
		Domain:      domain,
		Difficulty:  cfg.Difficulty,
		RedirectURL: redirectURL,
	}

	if err := altchaTpl.Execute(w, data); err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to execute template: %v", err))
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func handleAltchaChallenge(w http.ResponseWriter, r *http.Request) {
	domain := r.Host
	if i := strings.IndexByte(domain, ':'); i > -1 {
		domain = domain[:i]
	}

	difficulty := 12
	if d := r.URL.Query().Get("difficulty"); d != "" {
		if parsed, err := parseInt(d); err == nil {
			difficulty = parsed
		}
	}

	challenge, err := GenerateAltchaChallenge(domain, difficulty)
	if err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to generate challenge: %v", err))
		http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(challenge)
}

func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func handleAltchaVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AltchaVerification
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to decode request: %v", err))
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Payload == "" {
		ui.SystemLog("error", "altcha", "No payload in request")
		http.Error(w, "Payload required", http.StatusBadRequest)
		return
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to decode base64 payload: %v", err))
		http.Error(w, "Invalid payload encoding", http.StatusBadRequest)
		return
	}

	var decoded AltchaDecodedPayload
	if err := json.Unmarshal(decodedBytes, &decoded); err != nil {
		ui.SystemLog("error", "altcha", fmt.Sprintf("Failed to decode JSON payload: %v", err))
		http.Error(w, "Invalid payload format", http.StatusBadRequest)
		return
	}

	clientIP := r.RemoteAddr
	if i := strings.IndexByte(clientIP, ':'); i > -1 {
		clientIP = clientIP[:i]
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = r.Host
		if i := strings.IndexByte(domain, ':'); i > -1 {
			domain = domain[:i]
		}
	}

	if domain == "" {
		ui.SystemLog("error", "altcha", "No domain provided")
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	payload := AltchaPayload{
		Algorithm: decoded.Algorithm,
		Challenge: decoded.Challenge,
		Number:    decoded.Number,
		Salt:      decoded.Salt,
		Signature: decoded.Signature,
		MaxNumber: decoded.MaxNumber,
	}
	payloadJSON, _ := json.Marshal(payload)

	if !VerifyAltchaSolution(string(payloadJSON), domain) {
		ui.SystemLog("warn", "altcha", "Verification failed for "+clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(AltchaVerificationResponse{Verified: false})
		return
	}

	SetVerifiedCookie(w, clientIP)

	ui.SystemLog("info", "altcha", "ALTCHA verification successful")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AltchaVerificationResponse{
		Verified: true,
		Redirect: "/",
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
