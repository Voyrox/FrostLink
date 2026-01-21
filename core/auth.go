package core

import (
	"crypto/rand"
	"strings"
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

type Permission string

const (
	PermissionViewDashboard Permission = "view_dashboard"
	PermissionViewAnalytics Permission = "view_analytics"
	PermissionViewLogs      Permission = "view_logs"
	PermissionManageDomains Permission = "manage_domains"
	PermissionManageUsers   Permission = "manage_users"
	PermissionManageRoles   Permission = "manage_roles"
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

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func MigrateSingleIdentityProvider() {
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
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
