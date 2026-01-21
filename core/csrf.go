package core

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type CSRFToken struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

type csrfFile struct {
	Tokens []CSRFToken `json:"tokens"`
}

var (
	csrfMu     sync.RWMutex
	csrfTokens = make(map[string]CSRFToken)
	csrfOnce   sync.Once
)

func initCSRF() {
	csrfOnce.Do(func() {
		csrfMu.Lock()
		defer csrfMu.Unlock()

		data, err := os.ReadFile(csrfPath)
		if err != nil {
			if os.IsNotExist(err) {
				csrfTokens = make(map[string]CSRFToken)
			}
			return
		}

		var cf csrfFile
		if err := json.Unmarshal(data, &cf); err != nil {
			csrfTokens = make(map[string]CSRFToken)
			return
		}

		for _, t := range cf.Tokens {
			if t.CreatedAt.After(time.Now().Add(-1 * time.Hour)) {
				csrfTokens[t.SessionID] = t
			}
		}
	})
}

func saveCSRFUnlocked() {
	tf := csrfFile{Tokens: make([]CSRFToken, 0, len(csrfTokens))}
	for _, t := range csrfTokens {
		tf.Tokens = append(tf.Tokens, t)
	}

	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(csrfPath), 0755); err != nil {
		return
	}
	os.WriteFile(csrfPath, data, 0600)
}

func GenerateCSRFToken(sessionID string) string {
	csrfMu.Lock()
	defer csrfMu.Unlock()

	token := hex.EncodeToString(randomBytes(32))

	t := CSRFToken{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		Token:     token,
		CreatedAt: time.Now(),
	}
	csrfTokens[sessionID] = t
	saveCSRFUnlocked()

	return token
}

func ValidateCSRFToken(sessionID, token string) bool {
	initCSRF()
	csrfMu.RLock()
	defer csrfMu.RUnlock()

	t, ok := csrfTokens[sessionID]
	if !ok {
		return false
	}
	if !hmac.Equal([]byte(t.Token), []byte(token)) {
		return false
	}
	if t.CreatedAt.Before(time.Now().Add(-1 * time.Hour)) {
		return false
	}
	return true
}

func InvalidateCSRFToken(sessionID string) {
	csrfMu.Lock()
	defer csrfMu.Unlock()
	delete(csrfTokens, sessionID)
	saveCSRFUnlocked()
}
