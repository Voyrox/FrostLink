package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Role       string    `json:"role"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastAccess time.Time `json:"last_accessed"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type sessionFile struct {
	Sessions []Session `json:"sessions"`
}

var (
	sessionsMu   sync.RWMutex
	sessions     = make(map[string]Session)
	sessionsOnce sync.Once
)

func initSessions() {
	sessionsOnce.Do(func() {
		sessionsMu.Lock()
		defer sessionsMu.Unlock()

		data, err := os.ReadFile(sessionsPath)
		if err != nil {
			if os.IsNotExist(err) {
				sessions = make(map[string]Session)
			}
			return
		}

		var sf sessionFile
		if err := json.Unmarshal(data, &sf); err != nil {
			sessions = make(map[string]Session)
			return
		}

		for _, s := range sf.Sessions {
			if s.ExpiresAt.After(time.Now()) {
				sessions[s.ID] = s
			}
		}
	})
}

func saveSessionsUnlocked() {
	sf := sessionFile{Sessions: make([]Session, 0, len(sessions))}
	for _, s := range sessions {
		sf.Sessions = append(sf.Sessions, s)
	}

	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(sessionsPath), 0755); err != nil {
		return
	}
	os.WriteFile(sessionsPath, data, 0600)
}

func CreateSession(username, role, ip, userAgent string) string {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	now := time.Now()
	s := Session{
		ID:         uuid.NewString(),
		Username:   username,
		Role:       role,
		IP:         ip,
		UserAgent:  userAgent,
		CreatedAt:  now,
		LastAccess: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	sessions[s.ID] = s
	saveSessionsUnlocked()
	return s.ID
}

func GetSession(id string) (Session, bool) {
	initSessions()
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	s, ok := sessions[id]
	return s, ok
}

func UpdateSessionLastAccess(id string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if s, ok := sessions[id]; ok {
		s.LastAccess = time.Now()
		sessions[id] = s
		saveSessionsUnlocked()
	}
}

func RevokeSession(id string) bool {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if _, ok := sessions[id]; ok {
		delete(sessions, id)
		saveSessionsUnlocked()
		return true
	}
	return false
}

func RevokeSessionsByUser(username string) int {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	removed := 0
	for id, s := range sessions {
		if s.Username == username {
			delete(sessions, id)
			removed++
		}
	}
	if removed > 0 {
		saveSessionsUnlocked()
	}
	return removed
}

func ListSessions() []Session {
	initSessions()
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	result := make([]Session, 0, len(sessions))
	for _, s := range sessions {
		result = append(result, s)
	}
	return result
}

func CountSessionsByUser(username string) int {
	initSessions()
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	count := 0
	for _, s := range sessions {
		if s.Username == username {
			count++
		}
	}
	return count
}

func ValidateSession(id string) bool {
	initSessions()
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	s, ok := sessions[id]
	if !ok {
		return false
	}
	if s.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}
