package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"

	filepkg "SparkProxy/file"
	proxyhttp "SparkProxy/http"
	logger "SparkProxy/logger"
	userpkg "SparkProxy/user"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type FirewallStats struct {
	Blocked     int      `json:"blocked"`
	Whitelisted []string `json:"whitelisted"`
	Blacklisted []string `json:"blacklisted"`
}

type SystemStats struct {
	Firewall FirewallStats `json:"firewall"`
}

type DDoSStats struct {
	Blocked int `json:"blocked"`
}

type DataUsage struct {
	Upload   int `json:"upload"`
	Download int `json:"download"`
}

type ProxyDomainStats struct {
	TotalConnections int        `json:"total_connections"`
	LastActive       string     `json:"last_active"`
	TotalRequest     int        `json:"total_request"`
	TotalResponse    int        `json:"total_response"`
	Log              []LogEntry `json:"log"`
}

type LogEntry struct {
	Domain string  `json:"domain"`
	IP     string  `json:"ip"`
	Path   *string `json:"path"`
	Event  string  `json:"event"`
	Time   string  `json:"time"`
}

type ProxyStatistics struct {
	System  SystemStats                 `json:"system"`
	DDoS    DDoSStats                   `json:"ddos_attacks"`
	Data    DataUsage                   `json:"data_usage"`
	Proxies map[string]ProxyDomainStats `json:"proxies"`
}

var (
	sessions   = map[string]string{}
	sessionsMu sync.RWMutex
)

func main() {
	loadEnv(".env")
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	tpl := template.Must(template.ParseGlob("./views/*.tmpl"))
	r.SetHTMLTemplate(tpl)

	_ = r.SetTrustedProxies([]string{"127.0.0.1", "::1"})

	r.Static("/css", "./public/css")
	r.Static("/js", "./public/js")
	r.Static("/img", "./public/img")
	r.Static("/public", "./public")

	r.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "login", gin.H{}) })
	r.GET("/login", func(c *gin.Context) { c.HTML(http.StatusOK, "login", gin.H{}) })
	r.POST("/login", loginPost)
	r.GET("/dashboard", func(c *gin.Context) { c.HTML(http.StatusOK, "dashboard", gin.H{"ActivePage": "dashboard"}) })
	r.GET("/domains", func(c *gin.Context) { c.HTML(http.StatusOK, "domains", gin.H{"ActivePage": "domains"}) })
	r.GET("/analytics", func(c *gin.Context) { c.HTML(http.StatusOK, "analytics", gin.H{"ActivePage": "analytics"}) })
	r.GET("/logs", func(c *gin.Context) { c.HTML(http.StatusOK, "logs", gin.H{"ActivePage": "logs"}) })
	r.GET("/users", func(c *gin.Context) { c.HTML(http.StatusOK, "users", gin.H{"ActivePage": "users"}) })
	r.GET("/sidebar", func(c *gin.Context) { c.HTML(http.StatusOK, "sidebar", gin.H{"ActivePage": ""}) })
	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "404", gin.H{})
	})
	r.POST("/api/login", apiLogin)
	r.GET("/api/proxys", apiProxys)
	r.PUT("/api/domains/:domain/auth", apiDomainAuthUpdate)
	r.GET("/api/logs", apiLogs)
	r.GET("/api/users", apiUsersList)
	r.POST("/api/users", apiUsersCreate)
	r.DELETE("/api/users/:username", apiUsersDelete)

	go func() {
		cfgs := filepkg.ReadConfigs("./domains")
		if err := proxyhttp.StartProxy(cfgs); err != nil {
			logger.SystemLog("error", "proxy", fmt.Sprintf("Proxy error: %v", err))
		}
	}()

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	logger.SystemLog("info", "dashboard", fmt.Sprintf("Started on %s", addr))
	r.Run(addr)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createUserRequest struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Email      string   `json:"email"`
	Role       string   `json:"role"`
	AccessType string   `json:"access_type"`
	Domains    []string `json:"domains"`
}

func apiLogin(c *gin.Context) {
	var req loginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	validUser := os.Getenv("USER")
	validPass := os.Getenv("PASSWORD")

	if req.Username == validUser && req.Password == validPass && validUser != "" && validPass != "" {
		sid := uuid.NewString()
		sessionsMu.Lock()
		sessions[sid] = req.Username
		sessionsMu.Unlock()
		c.SetCookie("session", sid, 3600*24, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"valid": true, "session_id": sid})
		return
	}

	if u, ok := userpkg.Authenticate(req.Username, req.Password); ok && u != nil {
		sid := uuid.NewString()
		sessionsMu.Lock()
		sessions[sid] = u.Username
		sessionsMu.Unlock()
		c.SetCookie("session", sid, 3600*24, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"valid": true, "session_id": sid})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": false})
}

func apiProxys(c *gin.Context) {
	configs := filepkg.ReadConfigs("./domains")
	statSlice := proxyhttp.GetDomainStats()
	stats := make(map[string]proxyhttp.DomainStats)
	for _, s := range statSlice {
		stats[s.Domain] = s
	}

	var cfgsOut []map[string]interface{}
	for _, cfg := range configs {
		m := map[string]interface{}{
			"domain":  cfg.Domain,
			"host":    cfg.Location,
			"SSL":     cfg.AllowSSL,
			"HTTP":    cfg.AllowHTTP,
			"pubkey":  cfg.SSLCertificate,
			"privkey": cfg.SSLCertificateKey,
		}

		m["require_auth"] = proxyhttp.GetDomainAuth(cfg.Domain)
		if ps, ok := stats[cfg.Domain]; ok {
			m["data_in_total"] = ps.DataInTotal
			m["data_out_total"] = ps.DataOutTotal
			m["total_requests"] = ps.TotalRequests
			m["last_ip"] = ps.LastIP
			m["last_country"] = ps.LastCountry
			m["last_path"] = ps.LastPath
		} else {
			m["data_in_total"] = 0
			m["data_out_total"] = 0
			m["total_requests"] = 0
		}
		cfgsOut = append(cfgsOut, m)
	}

	c.JSON(http.StatusOK, gin.H{"configs": cfgsOut})
}

func apiLogs(c *gin.Context) {
	logs := proxyhttp.GetRequestLogs()
	var out []map[string]interface{}
	for _, l := range logs {
		out = append(out, map[string]interface{}{
			"timestamp": l.Timestamp.Format("2006-01-02 15:04:05"),
			"action":    l.Action,
			"ip":        l.IP,
			"location":  l.Country,
			"host":      l.Host,
			"path":      l.Path,
			"method":    l.Method,
		})
	}
	c.JSON(http.StatusOK, gin.H{"logs": out})
}

func apiUsersList(c *gin.Context) {
	users := userpkg.List()
	var out []map[string]interface{}
	for _, u := range users {
		out = append(out, map[string]interface{}{
			"username":          u.Username,
			"email":             u.Email,
			"identity_provider": u.IdentityProvider,
			"role":              u.Role,
			"access_type":       u.AccessType,
			"domains":           u.AllowedDomainList,
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": out})
}

func apiUsersCreate(c *gin.Context) {
	var req createUserRequest
	if err := c.BindJSON(&req); err != nil {
		logger.SystemLog("error", "api_users_create", fmt.Sprintf("invalid payload: %v", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Role == "" {
		req.Role = "Member"
	}
	u, err := userpkg.Create(req.Username, req.Email, req.Password, req.Role, req.AccessType, req.Domains)
	if err != nil {
		logger.SystemLog("error", "api_users_create", fmt.Sprintf("failed to create user '%s': %v", req.Username, err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.SystemLog("success", "api_users_create", fmt.Sprintf("created user '%s' (%s)", u.Username, u.Email))
	c.JSON(http.StatusOK, gin.H{"user": map[string]interface{}{
		"username":          u.Username,
		"email":             u.Email,
		"identity_provider": u.IdentityProvider,
		"role":              u.Role,
		"access_type":       u.AccessType,
		"domains":           u.AllowedDomainList,
	}})
}

func apiUsersDelete(c *gin.Context) {
	username := c.Param("username")
	if err := userpkg.Delete(username); err != nil {
		logger.SystemLog("error", "api_users_delete", fmt.Sprintf("failed to delete user '%s': %v", username, err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.SystemLog("success", "api_users_delete", fmt.Sprintf("deleted user '%s'", username))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type domainAuthRequest struct {
	RequireAuth bool `json:"require_auth"`
}

func apiDomainAuthUpdate(c *gin.Context) {
	domain := c.Param("domain")
	if strings.TrimSpace(domain) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	var req domainAuthRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if err := proxyhttp.SetDomainAuth(domain, req.RequireAuth); err != nil {
		logger.SystemLog("error", "api_domain_auth", fmt.Sprintf("failed to update auth for %s: %v", domain, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update auth"})
		return
	}
	logger.SystemLog("info", "api_domain_auth", fmt.Sprintf("domain %s auth set to %v", domain, req.RequireAuth))
	c.JSON(http.StatusOK, gin.H{"domain": domain, "require_auth": req.RequireAuth})
}

func loginPost(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	validUser := os.Getenv("USER")
	validPass := os.Getenv("PASSWORD")

	if email == validUser && password == validPass && validUser != "" && validPass != "" {
		sid := uuid.NewString()
		sessionsMu.Lock()
		sessions[sid] = email
		sessionsMu.Unlock()
		c.SetCookie("session", sid, 3600*24, "/", "", false, true)
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "Logged in successfully, redirecting…",
			"Redirect":     "/dashboard",
		})
		return
	}

	if u, ok := userpkg.Authenticate(email, password); ok && u != nil {
		sid := uuid.NewString()
		sessionsMu.Lock()
		sessions[sid] = u.Username
		sessionsMu.Unlock()
		c.SetCookie("session", sid, 3600*24, "/", "", false, true)
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "Logged in successfully, redirecting…",
			"Redirect":     "/dashboard",
		})
		return
	}

	c.HTML(http.StatusOK, "login", gin.H{
		"ToastMessage": "Invalid credentials. Please try again.",
	})
}

func loadEnv(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx > -1 {
			line = strings.TrimSpace(line[:idx])
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		val = strings.Trim(val, " \"'")
		_ = os.Setenv(key, val)
	}
}
