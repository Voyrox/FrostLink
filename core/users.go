package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SparkProxy/core/identity"
	"golang.org/x/crypto/bcrypt"
)

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

func LinkIdentityProviderToUser(username string, provider identity.IdentityProvider, email, oauthUserID string) error {
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
