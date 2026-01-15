package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

const sessionsPath = "db/sessions.json"

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
	mu       sync.RWMutex
	sessions = make(map[string]Session)
)

func init() {
	loadSessions()
	go cleanupRoutine()
}

func loadSessions() {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(sessionsPath)
	if err != nil {
		if os.IsNotExist(err) {
			sessions = make(map[string]Session)
			return
		}
		sessions = make(map[string]Session)
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
}

func saveSessions() {
	mu.Lock()
	defer mu.Unlock()
	saveSessionsUnlocked()
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
	if err := os.MkdirAll(filepath.Dir(sessionsPath), 0o755); err != nil {
		return
	}
	os.WriteFile(sessionsPath, data, 0o600)
}

func cleanupRoutine() {
	for {
		time.Sleep(5 * time.Minute)
		mu.Lock()
		now := time.Now()
		var removed int
		for id, s := range sessions {
			if s.ExpiresAt.Before(now) {
				delete(sessions, id)
				removed++
			}
		}
		if removed > 0 {
			saveSessionsUnlocked()
		}
		mu.Unlock()
	}
}

func Create(username, role, ip, userAgent string) string {
	mu.Lock()
	defer mu.Unlock()

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

func Get(id string) (Session, bool) {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := sessions[id]
	return s, ok
}

func UpdateLastAccess(id string) {
	mu.Lock()
	defer mu.Unlock()
	if s, ok := sessions[id]; ok {
		s.LastAccess = time.Now()
		sessions[id] = s
		saveSessionsUnlocked()
	}
}

func Revoke(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := sessions[id]; ok {
		delete(sessions, id)
		saveSessionsUnlocked()
		return true
	}
	return false
}

func RevokeByUser(username string) int {
	mu.Lock()
	defer mu.Unlock()
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

func List() []Session {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]Session, 0, len(sessions))
	for _, s := range sessions {
		result = append(result, s)
	}
	return result
}

func CountByUser(username string) int {
	mu.RLock()
	defer mu.RUnlock()

	count := 0
	for _, s := range sessions {
		if s.Username == username {
			count++
		}
	}
	return count
}

func Validate(id string) bool {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := sessions[id]
	if !ok {
		return false
	}
	if s.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}

func ForEach(fn func(Session)) {
	mu.RLock()
	defer mu.RUnlock()
	for _, s := range sessions {
		fn(s)
	}
}
