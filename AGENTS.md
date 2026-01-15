# AGENTS.md - SparkProxy Development Guide

This document provides guidelines for agentic coding agents working on the SparkProxy project.

## Project Overview

SparkProxy is a Go-based reverse proxy with HTTP/HTTPS support, a web dashboard, and domain management features. The project uses Go 1.21, Gin-Gonic web framework, and stores configuration in JSON files.

## Build Commands

```bash
# Build the application
go build -o SparkProxy main.go

# Build all packages
go build ./...

# Run the application
go run main.go

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o sparkproxy-linux main.go
```

## Lint and Test Commands

```bash
# Run all tests
go test ./...

# Run a single test file
go test -v ./http/...

# Run a single test function
go test -v -run TestFunctionName ./http/

# Run tests with coverage
go test -cover ./...

# Check for vet issues
go vet ./...

# Format code
gofmt -w .

# Check formatting without modifying
gofmt -d .

# View dependencies
go list -m all
```

## Code Style Guidelines

### Imports

Organize imports in three groups separated by blank lines:
1. Standard library packages
2. Third-party packages
3. Local packages (using module name `SparkProxy` with descriptive aliases)

```go
import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"

    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/bcrypt"

    filepkg "SparkProxy/file"
    proxyhttp "SparkProxy/http"
    logger "SparkProxy/logger"
)
```

### Naming Conventions

- **Variables**: camelCase (e.g., `domainStats`, `requestLogs`)
- **Constants**: camelCase or SCREAMING_SNAKE_CASE for exported constants (e.g., `defaultTimeout`, `MAX_CONNECTIONS`)
- **Functions**: camelCase for unexported, PascalCase for exported (e.g., `loadDomainAuth`, `GetDomainAuth`)
- **Types**: PascalCase (e.g., `User`, `DomainStats`)
- **Packages**: simple lowercase names (e.g., `http`, `user`, `logger`)
- **Files**: lowercase with underscores if needed (e.g., `mod.go`, `auth.go`)

### Structs and JSON

- Use PascalCase for exported struct fields
- Add JSON struct tags with snake_case keys
- Use descriptive field names that match API responses
- Prefer explicit structs over `map[string]interface{}`

```go
type User struct {
    Username          string   `json:"username"`
    Email             string   `json:"email"`
    PasswordHash      string   `json:"password_hash"`
    Role              string   `json:"role"`
    AllowedDomainList []string `json:"domains"`
}

type DomainStats struct {
    Domain        string `json:"domain"`
    DataInTotal   int64  `json:"data_in_total"`
    TotalRequests int64  `json:"total_requests"`
}
```

### Error Handling

- Return errors explicitly from functions that can fail
- Use `errors.New()` for simple errors
- Use `fmt.Errorf()` with `%w` for wrapped errors
- Check errors immediately after calling functions
- Log errors using `logger.SystemLog()` before returning when appropriate

```go
func SetDomainAuth(domain string, require bool) error {
    d := strings.ToLower(strings.TrimSpace(domain))
    if d == "" {
        return fmt.Errorf("domain is required")
    }

    authCfgMu.Lock()
    defer authCfgMu.Unlock()

    data, err := json.MarshalIndent(f, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(authCfgPath, data, 0o600)
}
```

### Thread Safety

- Use `sync.Mutex` or `sync.RWMutex` for protecting shared data
- Use `sync.Once` for one-time initialization
- Always use deferred unlocks with Lock()
- Check double-checked locking pattern for loaded flags

```go
var (
    authCfgMu   sync.RWMutex
    domainAuth  map[string]bool
    authCfgOnce sync.Once
)

func loadDomainAuth() {
    authCfgOnce.Do(func() {
        authCfgMu.Lock()
        defer authCfgMu.Unlock()
        // initialization
    })
}
```

### File Paths and Permissions

- Use `filepath.Join()` for constructing paths
- Use `os.Getenv()` for environment variables
- Set file permissions to `0o600` for sensitive data (users.json, domain_auth.json)
- Set directory permissions to `0o755` for created directories

```go
usersPath = filepath.Join(".", "db", "users.json")

func save() error {
    if err := os.MkdirAll(filepath.Dir(usersPath), 0o755); err != nil {
        return err
    }
    return os.WriteFile(usersPath, data, 0o600)
}
```

### JSON Handling

- Use `json.MarshalIndent()` with 2-space indentation for human-readable output
- Use `json.Unmarshal()` for parsing
- Handle missing files gracefully with `os.IsNotExist()`

```go
func load() {
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
        return
    }
    users = uf.Users
}
```

### Logging

- Use `logger.SystemLog(level, component, message)` for logging
- Levels: "info", "error", "warn", "debug"
- Include context in log messages

### Web Routes (Gin)

- Use Gin router with grouped routes for related endpoints
- Set mode to `gin.ReleaseMode` in production
- Use `c.JSON()` for JSON responses, `c.HTML()` for templates
- Return appropriate HTTP status codes

```go
gin.SetMode(gin.ReleaseMode)
r := gin.Default()

r.GET("/domains", func(c *gin.Context) {
    c.HTML(http.StatusOK, "domains", gin.H{"ActivePage": "domains"})
})
```

### Code Organization

- Keep related functionality in packages (http/, user/, file/, logger/, ssl/)
- Use `mod.go` for main package functionality, split into separate files when complex
- Export only necessary types and functions
- Use init() functions sparingly, prefer explicit initialization
