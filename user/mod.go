package user

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"SparkProxy/role"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username          string   `json:"username"`
	Email             string   `json:"email"`
	PasswordHash      string   `json:"password_hash"`
	IdentityProvider  string   `json:"identity_provider"`
	Role              string   `json:"role"`
	AccessType        string   `json:"access_type"`
	AllowedDomainList []string `json:"domains"`
}

type userFile struct {
	Users []User `json:"users"`
}

var (
	usersMu     sync.RWMutex
	users       []User
	usersLoaded bool

	usersPath = filepath.Join(".", "db", "users.json")
)

func load() {
	if usersLoaded {
		return
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	if usersLoaded {
		return
	}
	b, err := os.ReadFile(usersPath)
	if err != nil {
		if os.IsNotExist(err) {
			users = []User{}
			usersLoaded = true
			return
		}
		users = []User{}
		usersLoaded = true
		return
	}
	var uf userFile
	if err := json.Unmarshal(b, &uf); err != nil {
		users = []User{}
		usersLoaded = true
		return
	}
	users = uf.Users
	usersLoaded = true
}

func save() error {
	// NOTE: callers must hold the appropriate lock on usersMu
	data, err := json.MarshalIndent(userFile{Users: users}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(usersPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(usersPath, data, 0o600)
}

func List() []User {
	load()
	usersMu.RLock()
	defer usersMu.RUnlock()
	out := make([]User, len(users))
	for i, u := range users {
		out[i] = u
		out[i].PasswordHash = ""
	}
	return out
}

func Create(username, email, password, roleName, accessType string, domains []string) (User, error) {
	if username == "" || password == "" {
		return User{}, errors.New("username and password are required")
	}
	if roleName == "" {
		roleName = "Member"
	}
	if _, ok := role.Get(roleName); !ok {
		return User{}, errors.New("role does not exist")
	}
	if accessType != "all" && accessType != "custom" {
		accessType = "all"
	}
	load()
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
		IdentityProvider:  "Local",
		Role:              roleName,
		AccessType:        accessType,
		AllowedDomainList: allowed,
	}
	users = append(users, u)
	if err := save(); err != nil {
		return User{}, err
	}
	u.PasswordHash = ""
	return u, nil
}

func Delete(username string) error {
	if username == "" {
		return errors.New("username is required")
	}
	load()
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
	return save()
}

func Authenticate(username, password string) (*User, bool) {
	if username == "" || password == "" {
		return nil, false
	}
	load()
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
