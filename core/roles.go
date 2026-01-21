package core

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
