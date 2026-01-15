package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const tokensPath = "db/api_tokens.json"

type Token struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	TokenHash   string     `json:"token_hash"`
	Permission  string     `json:"permission"` // "read" or "write"
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Active      bool       `json:"active"`
}

type tokenFile struct {
	Tokens []Token `json:"tokens"`
}

var (
	mu     sync.RWMutex
	tokens = make(map[string]Token)
)

func init() {
	loadTokens()
}

func loadTokens() {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(tokensPath)
	if err != nil {
		if os.IsNotExist(err) {
			tokens = make(map[string]Token)
			return
		}
		tokens = make(map[string]Token)
		return
	}

	var tf tokenFile
	if err := json.Unmarshal(data, &tf); err != nil {
		tokens = make(map[string]Token)
		return
	}

	for _, t := range tf.Tokens {
		if t.Active && (t.ExpiresAt == nil || t.ExpiresAt.After(time.Now())) {
			tokens[t.ID] = t
		}
	}
}

func saveTokens() {
	mu.Lock()
	defer mu.Unlock()
	saveTokensUnlocked()
}

func saveTokensUnlocked() {
	tf := tokenFile{Tokens: make([]Token, 0, len(tokens))}
	for _, t := range tokens {
		tf.Tokens = append(tf.Tokens, t)
	}

	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(tokensPath), 0o755); err != nil {
		return
	}
	os.WriteFile(tokensPath, data, 0o600)
}

func GenerateToken() (fullToken, tokenID, prefix string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", "", err
	}
	fullToken = "spk_" + base64.RawURLEncoding.EncodeToString(raw)
	tokenID = uuid.NewString()
	prefix = fullToken[len(fullToken)-10:]

	return fullToken, tokenID, prefix, nil
}

func HashToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func Create(name, permission, createdBy string, expiresInDays *int) (fullToken string, err error) {
	fullToken, tokenID, prefix, err := GenerateToken()
	if err != nil {
		return "", err
	}

	hash, err := HashToken(fullToken)
	if err != nil {
		return "", err
	}

	now := time.Now()
	var expiresAt *time.Time
	if expiresInDays != nil && *expiresInDays > 0 {
		exp := now.AddDate(0, 0, *expiresInDays)
		expiresAt = &exp
	}

	t := Token{
		ID:          tokenID,
		Name:        name,
		TokenPrefix: prefix,
		TokenHash:   hash,
		Permission:  permission,
		CreatedBy:   createdBy,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		Active:      true,
	}

	mu.Lock()
	tokens[tokenID] = t
	saveTokensUnlocked()
	mu.Unlock()

	return fullToken, nil
}

func Validate(rawToken, requiredPermission string) (*Token, bool) {
	mu.RLock()
	defer mu.RUnlock()

	for _, t := range tokens {
		if !t.Active {
			continue
		}
		if t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()) {
			continue
		}
		if requiredPermission != "" && t.Permission != requiredPermission {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(t.TokenHash), []byte(rawToken)); err == nil {
			return &t, true
		}
	}
	return nil, false
}

func Get(id string) (Token, bool) {
	mu.RLock()
	defer mu.RUnlock()
	t, ok := tokens[id]
	return t, ok
}

func List() []Token {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]Token, 0, len(tokens))
	for _, t := range tokens {
		result = append(result, t)
	}
	return result
}

func ListPublic() []map[string]interface{} {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(tokens))
	for _, t := range tokens {
		result = append(result, map[string]interface{}{
			"id":           t.ID,
			"name":         t.Name,
			"token_prefix": t.TokenPrefix,
			"permission":   t.Permission,
			"created_by":   t.CreatedBy,
			"created_at":   t.CreatedAt.Format(time.RFC3339),
			"last_used":    t.LastUsedAt,
			"expires_at":   t.ExpiresAt,
			"active":       t.Active,
		})
	}
	return result
}

func Revoke(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := tokens[id]; ok {
		delete(tokens, id)
		saveTokensUnlocked()
		return true
	}
	return false
}

func UpdateLastUsed(id string) {
	mu.Lock()
	defer mu.Unlock()
	if t, ok := tokens[id]; ok {
		now := time.Now()
		t.LastUsedAt = &now
		tokens[id] = t
		saveTokensUnlocked()
	}
}
