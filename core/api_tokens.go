package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type APIToken struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	TokenPrefix    string     `json:"token_prefix"`
	TokenHash      string     `json:"token_hash"`
	Permission     string     `json:"permission"`
	AllowedDomains []string   `json:"allowed_domains"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	Active         bool       `json:"active"`
}

type tokenFile struct {
	Tokens []APIToken `json:"tokens"`
}

var (
	tokensMu   sync.RWMutex
	tokens     = make(map[string]APIToken)
	tokensOnce sync.Once
)

func loadTokens() {
	tokensOnce.Do(func() {
		tokensMu.Lock()
		defer tokensMu.Unlock()

		data, err := os.ReadFile(tokensPath)
		if err != nil {
			if os.IsNotExist(err) {
				tokens = make(map[string]APIToken)
			}
			return
		}

		var tf tokenFile
		if err := json.Unmarshal(data, &tf); err != nil {
			tokens = make(map[string]APIToken)
			return
		}

		for _, t := range tf.Tokens {
			if t.Active && (t.ExpiresAt == nil || t.ExpiresAt.After(time.Now())) {
				tokens[t.ID] = t
			}
		}
	})
}

func saveTokensUnlocked() {
	tf := tokenFile{Tokens: make([]APIToken, 0, len(tokens))}
	for _, t := range tokens {
		tf.Tokens = append(tf.Tokens, t)
	}

	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(tokensPath), 0755); err != nil {
		return
	}
	os.WriteFile(tokensPath, data, 0600)
}

func GenerateAPIToken() (fullToken, tokenID, prefix string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", "", err
	}
	fullToken = "spk_" + base64.RawURLEncoding.EncodeToString(raw)
	tokenID = uuid.NewString()
	prefix = fullToken[len(fullToken)-10:]

	return fullToken, tokenID, prefix, nil
}

func HashAPIToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CreateAPIToken(name, permission, createdBy string, expiresInDays *int, allowedDomains []string) (fullToken string, err error) {
	fullToken, tokenID, prefix, err := GenerateAPIToken()
	if err != nil {
		return "", err
	}

	hash, err := HashAPIToken(fullToken)
	if err != nil {
		return "", err
	}

	now := time.Now()
	var expiresAt *time.Time
	if expiresInDays != nil && *expiresInDays > 0 {
		exp := now.AddDate(0, 0, *expiresInDays)
		expiresAt = &exp
	}

	var domains []string
	for _, d := range allowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			domains = append(domains, d)
		}
	}

	t := APIToken{
		ID:             tokenID,
		Name:           name,
		TokenPrefix:    prefix,
		TokenHash:      hash,
		Permission:     permission,
		AllowedDomains: domains,
		CreatedBy:      createdBy,
		CreatedAt:      now,
		ExpiresAt:      expiresAt,
		Active:         true,
	}

	tokensMu.Lock()
	tokens[tokenID] = t
	saveTokensUnlocked()
	tokensMu.Unlock()

	return fullToken, nil
}

func ValidateAPIToken(rawToken, requiredPermission, domain string) (*APIToken, bool) {
	loadTokens()
	tokensMu.RLock()
	defer tokensMu.RUnlock()

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
			if domain != "" && len(t.AllowedDomains) > 0 {
				domainLower := strings.ToLower(domain)
				allowed := false
				for _, d := range t.AllowedDomains {
					if strings.ToLower(d) == domainLower {
						allowed = true
						break
					}
				}
				if !allowed {
					continue
				}
			}
			return &t, true
		}
	}
	return nil, false
}

func GetAPIToken(id string) (APIToken, bool) {
	loadTokens()
	tokensMu.RLock()
	defer tokensMu.RUnlock()
	t, ok := tokens[id]
	return t, ok
}

func ListAPITokens() []APIToken {
	loadTokens()
	tokensMu.RLock()
	defer tokensMu.RUnlock()

	result := make([]APIToken, 0, len(tokens))
	for _, t := range tokens {
		result = append(result, t)
	}
	return result
}

func RevokeAPIToken(id string) bool {
	loadTokens()
	tokensMu.Lock()
	defer tokensMu.Unlock()
	if _, ok := tokens[id]; ok {
		delete(tokens, id)
		saveTokensUnlocked()
		return true
	}
	return false
}

func UpdateAPITokenLastUsed(id string) {
	loadTokens()
	tokensMu.Lock()
	defer tokensMu.Unlock()
	if t, ok := tokens[id]; ok {
		now := time.Now()
		t.LastUsedAt = &now
		tokens[id] = t
		saveTokensUnlocked()
	}
}

type PaginatedTokensResponse struct {
	Tokens     []map[string]interface{} `json:"tokens"`
	Total      int                      `json:"total"`
	Page       int                      `json:"page"`
	Limit      int                      `json:"limit"`
	TotalPages int                      `json:"total_pages"`
}

func ListPublicPaginated(page, limit int) PaginatedTokensResponse {
	loadTokens()
	tokensMu.RLock()
	defer tokensMu.RUnlock()

	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	allTokens := make([]map[string]interface{}, 0, len(tokens))
	for _, t := range tokens {
		allTokens = append(allTokens, map[string]interface{}{
			"id":              t.ID,
			"name":            t.Name,
			"token_prefix":    t.TokenPrefix,
			"permission":      t.Permission,
			"allowed_domains": t.AllowedDomains,
			"created_by":      t.CreatedBy,
			"created_at":      t.CreatedAt.Format(time.RFC3339),
			"last_used":       t.LastUsedAt,
			"expires_at":      t.ExpiresAt,
			"active":          t.Active,
		})
	}

	total := len(allTokens)
	totalPages := (total + limit - 1) / limit

	offset := (page - 1) * limit
	var tokenList []map[string]interface{}
	if offset < total {
		end := offset + limit
		if end > total {
			end = total
		}
		tokenList = allTokens[offset:end]
	}

	return PaginatedTokensResponse{
		Tokens:     tokenList,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
	}
}
