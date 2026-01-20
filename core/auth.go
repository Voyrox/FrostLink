package core

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const usersPath = "db/users.json"
const sessionsPath = "db/sessions.json"
const csrfPath = "db/csrf.json"
const tokensPath = "db/api_tokens.json"
const rolesPath = "db/roles.json"

type IdentityProviderLink struct {
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	OAuthUserID  string `json:"oauth_user_id"`
	Email        string `json:"email"`
	LinkedAt     string `json:"linked_at"`
}

type User struct {
	Username          string                 `json:"username"`
	Email             string                 `json:"email"`
	PasswordHash      string                 `json:"password_hash"`
	IdentityProviders []IdentityProviderLink `json:"identity_providers"`
	Role              string                 `json:"role"`
	AccessType        string                 `json:"access_type"`
	AllowedDomainList []string               `json:"domains"`
}

type userFile struct {
	Users []User `json:"users"`
}

var (
	usersMu     sync.RWMutex
	users       []User
	usersLoaded bool
)

func loadUsers() {
	if usersLoaded && len(users) > 0 {
		return
	}
	usersMu.Lock()
	if usersLoaded && len(users) > 0 {
		usersMu.Unlock()
		return
	}
	b, err := os.ReadFile(usersPath)
	if err != nil {
		if os.IsNotExist(err) {
			users = []User{}
		} else {
			users = []User{}
		}
		usersLoaded = true
		usersMu.Unlock()
		return
	}
	var uf userFile
	if err := json.Unmarshal(b, &uf); err != nil {
		users = []User{}
		usersLoaded = true
		usersMu.Unlock()
		return
	}
	users = uf.Users
	usersLoaded = true
	usersMu.Unlock()
}

func saveUsers() error {
	data, err := json.MarshalIndent(userFile{Users: users}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(usersPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(usersPath, data, 0600); err != nil {
		return err
	}
	usersLoaded = true
	return nil
}

func ListUsers() []User {
	loadUsers()
	usersMu.RLock()
	defer usersMu.RUnlock()
	out := make([]User, len(users))
	for i, u := range users {
		out[i] = u
		out[i].PasswordHash = ""
	}
	return out
}

func CreateUser(username, email, password, roleName, accessType string, domains []string) (User, error) {
	if username == "" || password == "" {
		return User{}, errors.New("username and password are required")
	}
	if roleName == "" {
		roleName = "Member"
	}
	if _, ok := GetRole(roleName); !ok {
		return User{}, errors.New("role does not exist")
	}
	if accessType != "all" && accessType != "custom" {
		accessType = "all"
	}
	loadUsers()
	usersMu.Lock()
	defer usersMu.Unlock()
	for _, u := range users {
		if u.Username == username {
			return User{}, errors.New("user already exists")
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	var allowed []string
	if accessType == "custom" {
		allowed = append(allowed, domains...)
	}
	u := User{
		Username:          username,
		Email:             email,
		PasswordHash:      string(hash),
		IdentityProviders: []IdentityProviderLink{},
		Role:              roleName,
		AccessType:        accessType,
		AllowedDomainList: allowed,
	}
	users = append(users, u)
	if err := saveUsers(); err != nil {
		return User{}, err
	}
	u.PasswordHash = ""
	return u, nil
}

func InitRootUser() {
	rootUser := os.Getenv("USER")
	rootPass := os.Getenv("PASSWORD")
	rootEmail := os.Getenv("ROOT_EMAIL")

	if rootUser == "" {
		rootUser = "root"
	}
	if rootPass == "" {
		rootPass = "1234567890"
	}
	if rootEmail == "" {
		rootEmail = "root@localhost"
	}

	loadUsers()
	usersMu.RLock()
	for _, u := range users {
		if u.Username == rootUser {
			usersMu.RUnlock()
			return
		}
	}
	usersMu.RUnlock()

	_, err := CreateUser(rootUser, rootEmail, rootPass, "Owner", "all", nil)
	if err != nil {
		fmt.Printf("Failed to create root user: %v\n", err)
	} else {
		fmt.Printf("Root user '%s' created successfully\n", rootUser)
	}
}

func DeleteUser(username string) error {
	if username == "" {
		return errors.New("username is required")
	}
	loadUsers()
	usersMu.Lock()
	defer usersMu.Unlock()
	idx := -1
	for i, u := range users {
		if u.Username == username {
			idx = i
			break
		}
	}
	if idx == -1 {
		return errors.New("user not found")
	}
	users = append(users[:idx], users[idx+1:]...)
	return saveUsers()
}

func AuthenticateUser(username, password string) (*User, bool) {
	if username == "" || password == "" {
		return nil, false
	}
	loadUsers()
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, u := range users {
		if u.Username != username {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
			return nil, false
		}
		copy := u
		copy.PasswordHash = ""
		return &copy, true
	}
	return nil, false
}

func IsProviderLinkedToUser(username, providerID string) bool {
	loadUsers()
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, u := range users {
		if u.Username != username {
			continue
		}
		for _, p := range u.IdentityProviders {
			if p.ProviderID == providerID {
				return true
			}
		}
	}
	return false
}

func LinkIdentityProviderToUser(username string, provider IdentityProvider, email, oauthUserID string) error {
	loadUsers()
	usersMu.Lock()
	defer usersMu.Unlock()

	for _, u := range users {
		for _, p := range u.IdentityProviders {
			if p.ProviderID == provider.ID && p.OAuthUserID == oauthUserID {
				return errors.New("this " + provider.Name + " account is already linked to another user")
			}
		}
	}

	for i := range users {
		if users[i].Username != username {
			continue
		}
		for _, p := range users[i].IdentityProviders {
			if p.ProviderID == provider.ID {
				return errors.New("provider already linked")
			}
		}
		users[i].IdentityProviders = append(users[i].IdentityProviders, IdentityProviderLink{
			ProviderID:   provider.ID,
			ProviderName: provider.Name,
			OAuthUserID:  oauthUserID,
			Email:        email,
			LinkedAt:     time.Now().Format(time.RFC3339),
		})
		return saveUsers()
	}
	return errors.New("user not found")
}

func UnlinkIdentityProviderFromUser(username, providerID string) error {
	loadUsers()
	usersMu.Lock()
	defer usersMu.Unlock()

	for i := range users {
		if users[i].Username != username {
			continue
		}
		linked := users[i].IdentityProviders
		idx := -1
		for j, p := range linked {
			if p.ProviderID == providerID {
				idx = j
				break
			}
		}
		if idx == -1 {
			return errors.New("provider not linked to user")
		}
		users[i].IdentityProviders = append(linked[:idx], linked[idx+1:]...)
		return saveUsers()
	}
	return errors.New("user not found")
}

func GetUserLinkedProviders(username string) []IdentityProviderLink {
	loadUsers()
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, u := range users {
		if u.Username == username {
			return u.IdentityProviders
		}
	}
	return nil
}

func GetUserByEmailWithProvider(email, providerID string) (*User, bool) {
	if email == "" {
		return nil, false
	}
	loadUsers()
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, u := range users {
		if !strings.EqualFold(u.Email, email) {
			continue
		}
		for _, p := range u.IdentityProviders {
			if p.ProviderID == providerID {
				copy := u
				copy.PasswordHash = ""
				return &copy, true
			}
		}
	}
	return nil, false
}

func MigrateSingleIdentityProvider() {
}

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
	sessionsInit bool
)

func initSessions() {
	if sessionsInit {
		return
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if sessionsInit {
		return
	}

	data, err := os.ReadFile(sessionsPath)
	if err != nil {
		if os.IsNotExist(err) {
			sessions = make(map[string]Session)
			sessionsInit = true
			return
		}
		sessions = make(map[string]Session)
		sessionsInit = true
		return
	}

	var sf sessionFile
	if err := json.Unmarshal(data, &sf); err != nil {
		sessions = make(map[string]Session)
		sessionsInit = true
		return
	}

	for _, s := range sf.Sessions {
		if s.ExpiresAt.After(time.Now()) {
			sessions[s.ID] = s
		}
	}
	sessionsInit = true
}

func saveSessions() {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
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
	csrfInit   bool
)

func initCSRF() {
	if csrfInit {
		return
	}
	csrfMu.Lock()
	defer csrfMu.Unlock()
	if csrfInit {
		return
	}

	data, err := os.ReadFile(csrfPath)
	if err != nil {
		if os.IsNotExist(err) {
			csrfTokens = make(map[string]CSRFToken)
			csrfInit = true
			return
		}
		csrfTokens = make(map[string]CSRFToken)
		csrfInit = true
		return
	}

	var cf csrfFile
	if err := json.Unmarshal(data, &cf); err != nil {
		csrfTokens = make(map[string]CSRFToken)
		csrfInit = true
		return
	}

	for _, t := range cf.Tokens {
		if t.CreatedAt.After(time.Now().Add(-1 * time.Hour)) {
			csrfTokens[t.SessionID] = t
		}
	}
	csrfInit = true
}

func saveCSRF() {
	csrfMu.Lock()
	defer csrfMu.Unlock()
	saveCSRFUnlocked()
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
	if t.Token != token {
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

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

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
	tokensMu     sync.RWMutex
	tokens       = make(map[string]APIToken)
	tokensLoaded bool
)

func loadTokens() {
	if tokensLoaded {
		return
	}
	tokensMu.Lock()
	defer tokensMu.Unlock()
	if tokensLoaded {
		return
	}

	data, err := os.ReadFile(tokensPath)
	if err != nil {
		if os.IsNotExist(err) {
			tokens = make(map[string]APIToken)
			tokensLoaded = true
			return
		}
		tokens = make(map[string]APIToken)
		tokensLoaded = true
		return
	}

	var tf tokenFile
	if err := json.Unmarshal(data, &tf); err != nil {
		tokens = make(map[string]APIToken)
		tokensLoaded = true
		return
	}

	for _, t := range tf.Tokens {
		if t.Active && (t.ExpiresAt == nil || t.ExpiresAt.After(time.Now())) {
			tokens[t.ID] = t
		}
	}
	tokensLoaded = true
}

func saveTokens() {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	saveTokensUnlocked()
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

type Permission string

const (
	PermissionViewDashboard Permission = "view_dashboard"
	PermissionViewAnalytics Permission = "view_analytics"
	PermissionViewLogs      Permission = "view_logs"
	PermissionManageDomains Permission = "manage_domains"
	PermissionManageUsers   Permission = "manage_users"
	PermissionManageRoles   Permission = "manage_roles"
)

type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	IsSystem    bool         `json:"is_system"`
}

type roleFile struct {
	Roles []Role `json:"roles"`
}

var (
	rolesMu     sync.RWMutex
	roles       []Role
	rolesLoaded bool
)

func AllPermissions() []Permission {
	return []Permission{
		PermissionViewDashboard,
		PermissionViewAnalytics,
		PermissionViewLogs,
		PermissionManageDomains,
		PermissionManageUsers,
		PermissionManageRoles,
	}
}

func loadRoles() {
	if rolesLoaded {
		return
	}
	rolesMu.Lock()
	defer rolesMu.Unlock()
	if rolesLoaded {
		return
	}
	b, err := os.ReadFile(rolesPath)
	if err != nil {
		if os.IsNotExist(err) {
			initializeDefaultRoles()
			return
		}
		roles = []Role{}
		rolesLoaded = true
		return
	}
	var rf roleFile
	if err := json.Unmarshal(b, &rf); err != nil {
		roles = []Role{}
		rolesLoaded = true
		return
	}
	roles = rf.Roles
	rolesLoaded = true
}

func initializeDefaultRoles() {
	owner := Role{
		Name:        "Owner",
		Description: "Full access to all features",
		Permissions: AllPermissions(),
		IsSystem:    true,
	}
	admin := Role{
		Name:        "Admin",
		Description: "Administrative access",
		Permissions: []Permission{
			PermissionManageUsers,
			PermissionManageRoles,
			PermissionManageDomains,
			PermissionViewLogs,
			PermissionViewAnalytics,
		},
		IsSystem: true,
	}
	member := Role{
		Name:        "Member",
		Description: "Standard user access",
		Permissions: []Permission{
			PermissionViewDashboard,
			PermissionViewAnalytics,
		},
		IsSystem: false,
	}
	roles = []Role{owner, admin, member}
	rolesLoaded = true
	if err := saveRoles(); err != nil {
		return
	}
}

func saveRoles() error {
	data, err := json.MarshalIndent(roleFile{Roles: roles}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rolesPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(rolesPath, data, 0600); err != nil {
		return err
	}
	rolesLoaded = true
	return nil
}

func ListRoles() []Role {
	loadRoles()
	rolesMu.RLock()
	defer rolesMu.RUnlock()
	out := make([]Role, len(roles))
	copy(out, roles)
	return out
}

func GetRole(name string) (Role, bool) {
	loadRoles()
	rolesMu.RLock()
	defer rolesMu.RUnlock()
	for _, r := range roles {
		if strings.EqualFold(r.Name, name) {
			return r, true
		}
	}
	return Role{}, false
}

func HasRolePermission(roleName string, permission Permission) bool {
	r, ok := GetRole(roleName)
	if !ok {
		return false
	}
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

func CreateRole(name, description string, permissions []Permission) (Role, error) {
	if name == "" {
		return Role{}, errors.New("role name is required")
	}
	if len(permissions) == 0 {
		return Role{}, errors.New("at least one permission is required")
	}
	loadRoles()
	rolesMu.Lock()
	defer rolesMu.Unlock()
	for _, r := range roles {
		if strings.EqualFold(r.Name, name) {
			return Role{}, errors.New("role already exists")
		}
	}
	role := Role{
		Name:        strings.TrimSpace(name),
		Description: strings.TrimSpace(description),
		Permissions: permissions,
		IsSystem:    false,
	}
	roles = append(roles, role)
	if err := saveRoles(); err != nil {
		return Role{}, err
	}
	return role, nil
}

func UpdateRole(name string, description string, permissions []Permission) (Role, error) {
	if name == "" {
		return Role{}, errors.New("role name is required")
	}
	loadRoles()
	rolesMu.Lock()
	defer rolesMu.Unlock()
	idx := -1
	for i, r := range roles {
		if strings.EqualFold(r.Name, name) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return Role{}, errors.New("role not found")
	}
	if roles[idx].IsSystem {
		return Role{}, errors.New("cannot modify system roles")
	}
	if len(permissions) == 0 {
		return Role{}, errors.New("at least one permission is required")
	}
	roles[idx].Description = strings.TrimSpace(description)
	roles[idx].Permissions = permissions
	if err := saveRoles(); err != nil {
		return Role{}, err
	}
	return roles[idx], nil
}

func DeleteRole(name string) error {
	if name == "" {
		return errors.New("role name is required")
	}
	loadRoles()
	rolesMu.Lock()
	defer rolesMu.Unlock()
	idx := -1
	for i, r := range roles {
		if strings.EqualFold(r.Name, name) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return errors.New("role not found")
	}
	if roles[idx].IsSystem {
		return errors.New("cannot delete system roles")
	}
	roles = append(roles[:idx], roles[idx+1:]...)
	return saveRoles()
}

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

	// Set default endpoints for Google
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

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type OAuthUserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Avatar   string `json:"avatar"`
}

func GetUserByEmail(email string) (*User, bool) {
	if email == "" {
		return nil, false
	}
	loadUsers()
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			copy := u
			copy.PasswordHash = ""
			return &copy, true
		}
	}
	return nil, false
}

func ExchangeOAuthCode(provider IdentityProvider, code, redirectURI string) (*OAuthToken, error) {
	if provider.TokenEndpoint == "" {
		return nil, errors.New("provider does not support token exchange")
	}

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	credentials := provider.ClientID + ":" + provider.ClientSecret
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

	req, err := http.NewRequest("POST", provider.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Basic "+encoded)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var token OAuthToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &token, nil
}

func FetchOAuthUserInfo(provider IdentityProvider, accessToken string) (*OAuthUserInfo, error) {
	var userInfoURL string
	if provider.ProviderType == "google" {
		userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	} else {
		userInfoURL = "https://discord.com/api/users/@me"
	}

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	body, _ := io.ReadAll(resp.Body)

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	var userInfo OAuthUserInfo
	if provider.ProviderType == "google" {
		userInfo.ID = getStringFromMap(rawData, "id")
		userInfo.Email = getStringFromMap(rawData, "email")
		userInfo.Username = getStringFromMap(rawData, "name")
		userInfo.Avatar = getStringFromMap(rawData, "picture")
	} else {
		userInfo.ID = getStringFromMap(rawData, "id")
		userInfo.Email = getStringFromMap(rawData, "email")
		userInfo.Username = getStringFromMap(rawData, "username")
		userInfo.Avatar = getStringFromMap(rawData, "avatar")
	}

	return &userInfo, nil
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
