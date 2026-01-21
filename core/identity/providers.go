package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type IdentityProvider struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ProviderType  string `json:"provider_type"`
	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	AuthEndpoint  string `json:"auth_endpoint,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
}

type identityProviderFile struct {
	Providers []IdentityProvider `json:"providers"`
}

var (
	providersMu     sync.RWMutex
	providers       []IdentityProvider
	providersLoaded bool
)

const providersPath = "db/identity_providers.json"

func loadProviders() {
	if providersLoaded {
		return
	}
	providersMu.Lock()
	defer providersMu.Unlock()
	if providersLoaded {
		return
	}
	b, err := os.ReadFile(providersPath)
	if err != nil {
		if os.IsNotExist(err) {
			providers = []IdentityProvider{}
			providersLoaded = true
			return
		}
		providers = []IdentityProvider{}
		providersLoaded = true
		return
	}
	var pf identityProviderFile
	if err := json.Unmarshal(b, &pf); err != nil {
		providers = []IdentityProvider{}
		providersLoaded = true
		return
	}
	providers = pf.Providers
	providersLoaded = true
}

func saveProviders() error {
	data, err := json.MarshalIndent(identityProviderFile{Providers: providers}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(providersPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(providersPath, data, 0600)
}

func ListIdentityProviders() []IdentityProvider {
	loadProviders()
	providersMu.RLock()
	defer providersMu.RUnlock()
	out := make([]IdentityProvider, len(providers))
	copy(out, providers)
	return out
}

func GetIdentityProvider(id string) (IdentityProvider, bool) {
	loadProviders()
	providersMu.RLock()
	defer providersMu.RUnlock()
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	return IdentityProvider{}, false
}

func CreateIdentityProvider(name, providerType, clientID, clientSecret, authEndpoint, tokenEndpoint string) (IdentityProvider, error) {
	if name == "" {
		return IdentityProvider{}, errors.New("name is required")
	}
	if providerType == "" {
		return IdentityProvider{}, errors.New("provider type is required")
	}
	if providerType != "google" && (clientID == "" || clientSecret == "") {
		return IdentityProvider{}, errors.New("client_id and client_secret are required")
	}
	if providerType == "google" && clientID == "" {
		return IdentityProvider{}, errors.New("Google Client ID is required")
	}

	if providerType == "google" {
		if authEndpoint == "" {
			authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
		}
		if tokenEndpoint == "" {
			tokenEndpoint = "https://oauth2.googleapis.com/token"
		}
	}

	loadProviders()
	providersMu.Lock()
	defer providersMu.Unlock()

	p := IdentityProvider{
		ID:            uuid.New().String(),
		Name:          strings.TrimSpace(name),
		ProviderType:  providerType,
		ClientID:      strings.TrimSpace(clientID),
		ClientSecret:  strings.TrimSpace(clientSecret),
		AuthEndpoint:  strings.TrimSpace(authEndpoint),
		TokenEndpoint: strings.TrimSpace(tokenEndpoint),
		Enabled:       true,
		CreatedAt:     time.Now().Format(time.RFC3339),
	}
	providers = append(providers, p)
	if err := saveProviders(); err != nil {
		return IdentityProvider{}, err
	}
	return p, nil
}

func DeleteIdentityProvider(id string) error {
	if id == "" {
		return errors.New("id is required")
	}
	loadProviders()
	providersMu.Lock()
	defer providersMu.Unlock()
	idx := -1
	for i, p := range providers {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return errors.New("provider not found")
	}
	providers = append(providers[:idx], providers[idx+1:]...)
	return saveProviders()
}

func ToggleIdentityProvider(id string, enabled bool) error {
	if id == "" {
		return errors.New("id is required")
	}
	loadProviders()
	providersMu.Lock()
	defer providersMu.Unlock()
	idx := -1
	for i, p := range providers {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return errors.New("provider not found")
	}
	providers[idx].Enabled = enabled
	return saveProviders()
}
