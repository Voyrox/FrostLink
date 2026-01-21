package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type PasskeyCredential struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"`
	SignCount    uint32 `json:"sign_count"`
	DeviceType   string `json:"device_type"`
	CreatedAt    string `json:"created_at"`
	LastUsedAt   string `json:"last_used_at"`
}

type passkeyFile struct {
	Credentials []PasskeyCredential `json:"credentials"`
}

var (
	passkeysMu     sync.RWMutex
	passkeys       []PasskeyCredential
	passkeysLoaded bool
)

const passkeysPath = "db/passkeys.json"

func loadPasskeys() {
	if passkeysLoaded {
		return
	}
	passkeysMu.Lock()
	defer passkeysMu.Unlock()
	if passkeysLoaded {
		return
	}
	b, err := os.ReadFile(passkeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			passkeys = []PasskeyCredential{}
			passkeysLoaded = true
			return
		}
		passkeys = []PasskeyCredential{}
		passkeysLoaded = true
		return
	}
	var pf passkeyFile
	if err := json.Unmarshal(b, &pf); err != nil {
		passkeys = []PasskeyCredential{}
		passkeysLoaded = true
		return
	}
	passkeys = pf.Credentials
	passkeysLoaded = true
}

func savePasskeys() error {
	data, err := json.MarshalIndent(passkeyFile{Credentials: passkeys}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(passkeysPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(passkeysPath, data, 0600)
}

func ListPasskeyCredentials(username string) []PasskeyCredential {
	loadPasskeys()
	passkeysMu.RLock()
	defer passkeysMu.RUnlock()
	var out []PasskeyCredential
	for _, p := range passkeys {
		if p.Username == username {
			out = append(out, p)
		}
	}
	return out
}

func GetPasskeyCredentialByID(credentialID []byte) *PasskeyCredential {
	loadPasskeys()
	passkeysMu.RLock()
	defer passkeysMu.RUnlock()
	for i := range passkeys {
		if bytes.Equal(passkeys[i].CredentialID, credentialID) {
			return &passkeys[i]
		}
	}
	return nil
}

func CreatePasskeyCredential(userID, username string, credentialID, publicKey []byte, signCount uint32, deviceType string) (PasskeyCredential, error) {
	if userID == "" || username == "" || len(credentialID) == 0 || len(publicKey) == 0 {
		return PasskeyCredential{}, errors.New("invalid parameters")
	}

	loadPasskeys()
	passkeysMu.Lock()
	defer passkeysMu.Unlock()

	p := PasskeyCredential{
		ID:           uuid.New().String(),
		UserID:       userID,
		Username:     username,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		SignCount:    signCount,
		DeviceType:   deviceType,
		CreatedAt:    time.Now().Format(time.RFC3339),
		LastUsedAt:   time.Now().Format(time.RFC3339),
	}
	passkeys = append(passkeys, p)
	if err := savePasskeys(); err != nil {
		return PasskeyCredential{}, err
	}
	return p, nil
}

func UpdatePasskeySignCount(credentialID []byte, newSignCount uint32) error {
	loadPasskeys()
	passkeysMu.Lock()
	defer passkeysMu.Unlock()
	for i := range passkeys {
		if bytes.Equal(passkeys[i].CredentialID, credentialID) {
			passkeys[i].SignCount = newSignCount
			passkeys[i].LastUsedAt = time.Now().Format(time.RFC3339)
			return savePasskeys()
		}
	}
	return errors.New("credential not found")
}

func DeletePasskeyCredential(id string) error {
	if id == "" {
		return errors.New("id is required")
	}
	loadPasskeys()
	passkeysMu.Lock()
	defer passkeysMu.Unlock()
	idx := -1
	for i, p := range passkeys {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return errors.New("credential not found")
	}
	passkeys = append(passkeys[:idx], passkeys[idx+1:]...)
	return savePasskeys()
}

func DeletePasskeyCredentialsByUser(username string) error {
	loadPasskeys()
	passkeysMu.Lock()
	defer passkeysMu.Unlock()
	var newCreds []PasskeyCredential
	for _, p := range passkeys {
		if p.Username != username {
			newCreds = append(newCreds, p)
		}
	}
	passkeys = newCreds
	return savePasskeys()
}
