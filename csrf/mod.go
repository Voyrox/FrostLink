package csrf

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

const csrfPath = "db/csrf.json"

type csrfFile struct {
	Tokens []CSRFToken `json:"tokens"`
}

type CSRFToken struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	mu     sync.RWMutex
	tokens = make(map[string]CSRFToken)
)

func init() {
	loadTokens()
	go cleanupRoutine()
}

func loadTokens() {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(csrfPath)
	if err != nil {
		if os.IsNotExist(err) {
			tokens = make(map[string]CSRFToken)
			return
		}
		tokens = make(map[string]CSRFToken)
		return
	}

	var cf csrfFile
	if err := json.Unmarshal(data, &cf); err != nil {
		tokens = make(map[string]CSRFToken)
		return
	}

	for _, t := range cf.Tokens {
		if t.CreatedAt.After(time.Now().Add(-1 * time.Hour)) {
			tokens[t.SessionID] = t
		}
	}
}

func saveTokens() {
	mu.Lock()
	defer mu.Unlock()
	saveTokensUnlocked()
}

func saveTokensUnlocked() {
	tf := csrfFile{Tokens: make([]CSRFToken, 0, len(tokens))}
	for _, t := range tokens {
		tf.Tokens = append(tf.Tokens, t)
	}

	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(csrfPath), 0o755); err != nil {
		return
	}
	os.WriteFile(csrfPath, data, 0o600)
}

func cleanupRoutine() {
	for {
		time.Sleep(10 * time.Minute)
		mu.Lock()
		cutoff := time.Now().Add(-1 * time.Hour)
		for sid, t := range tokens {
			if t.CreatedAt.Before(cutoff) {
				delete(tokens, sid)
			}
		}
		if len(tokens) > 0 {
			saveTokensUnlocked()
		}
		mu.Unlock()
	}
}

func GenerateToken(sessionID string) string {
	mu.Lock()
	defer mu.Unlock()

	token := hex.EncodeToString(randomBytes(32))

	t := CSRFToken{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		Token:     token,
		CreatedAt: time.Now(),
	}
	tokens[sessionID] = t
	saveTokensUnlocked()

	return token
}

func ValidateToken(sessionID, token string) bool {
	mu.RLock()
	defer mu.RUnlock()

	t, ok := tokens[sessionID]
	if !ok {
		return false
	}
	if t.Token != token {
		return false
	}
	if t.CreatedAt.Before(time.Now().Add(-1 * time.Hour)) {
		return false
	}
	return true
}

func InvalidateToken(sessionID string) {
	mu.Lock()
	defer mu.Unlock()
	delete(tokens, sessionID)
	saveTokensUnlocked()
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
