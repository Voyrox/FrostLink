package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	filepkg "SparkProxy/file"
	firewallpkg "SparkProxy/firewall"
	proxyhttp "SparkProxy/http"
	logger "SparkProxy/logger"
	rolepkg "SparkProxy/role"
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

type DashboardStats struct {
	ActiveUsers        int   `json:"active_users"`
	FirewallBlocked    int   `json:"firewall_blocked"`
	DDOSBlocked        int   `json:"ddos_blocked"`
	UploadBytesTotal   int64 `json:"upload_bytes_total"`
	DownloadBytesTotal int64 `json:"download_bytes_total"`
}

var (
	sessions   = map[string]string{}
	sessionsMu sync.RWMutex

	healthClient = &http.Client{Timeout: 1500 * time.Millisecond}
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
	r.GET("/firewall", func(c *gin.Context) { c.HTML(http.StatusOK, "firewall", gin.H{"ActivePage": "firewall"}) })
	r.GET("/roles", func(c *gin.Context) { c.HTML(http.StatusOK, "roles", gin.H{"ActivePage": "roles"}) })
	r.GET("/sidebar", func(c *gin.Context) { c.HTML(http.StatusOK, "sidebar", gin.H{"ActivePage": ""}) })
	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "404", gin.H{})
	})
	r.POST("/api/login", apiLogin)
	r.GET("/api/dashboard", apiDashboard)
	r.GET("/api/firewall", apiFirewallGet)
	r.POST("/api/firewall/ban-ip", apiFirewallBanIP)
	r.POST("/api/firewall/ban-ip-upload", apiFirewallBanIPUpload)
	r.POST("/api/firewall/ban-country", apiFirewallBanCountry)
	r.GET("/api/proxys", apiProxys)
	r.PUT("/api/domains/:domain/auth", apiDomainAuthUpdate)
	r.POST("/api/domains", apiDomainsCreate)
	r.GET("/api/logs", apiLogs)
	r.GET("/api/users", apiUsersList)
	r.POST("/api/users", apiUsersCreate)
	r.DELETE("/api/users/:username", apiUsersDelete)
	r.GET("/api/roles", apiRolesList)
	r.POST("/api/roles", apiRolesCreate)
	r.PUT("/api/roles/:name", apiRolesUpdate)
	r.DELETE("/api/roles/:name", apiRolesDelete)

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

type createDomainRequest struct {
	Domain   string `json:"domain"`
	Target   string `json:"target"`
	SSL      bool   `json:"ssl"`
	HTTP     bool   `json:"http"`
	CertMode string `json:"cert_mode"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

type firewallIPBanRequest struct {
	IP string `json:"ip"`
}

type firewallCountryBanRequest struct {
	Country   string   `json:"country"`
	Countries []string `json:"countries"`
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

		online := false
		if strings.TrimSpace(cfg.Location) != "" && cfg.AllowHTTP {
			if req, err := http.NewRequest("GET", "http"+"://"+strings.TrimSpace(cfg.Location), nil); err == nil {
				if resp, err := healthClient.Do(req); err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode < 400 {
						online = true
					}
				}
			}
		}
		m["online"] = online

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

func apiDashboard(c *gin.Context) {
	domainStats := proxyhttp.GetDomainStats()
	var uploadTotal int64
	var downloadTotal int64
	for _, ds := range domainStats {
		uploadTotal += ds.DataOutTotal
		downloadTotal += ds.DataInTotal
	}

	logs := proxyhttp.GetRequestLogs()
	ipSet := make(map[string]struct{})
	cutoff := time.Now().Add(-30 * time.Second)
	var firewallBlocked int
	var ddosBlocked int
	for _, l := range logs {
		if l.Timestamp.After(cutoff) {
			if l.IP != "" {
				ipSet[l.IP] = struct{}{}
			}
		}
		action := strings.ToLower(strings.TrimSpace(l.Action))
		if action != "" && action != "allow" {
			firewallBlocked++
			if strings.Contains(action, "ddos") {
				ddosBlocked++
			}
		}
	}

	stats := DashboardStats{
		ActiveUsers:        len(ipSet),
		FirewallBlocked:    firewallBlocked,
		DDOSBlocked:        ddosBlocked,
		UploadBytesTotal:   uploadTotal,
		DownloadBytesTotal: downloadTotal,
	}

	c.JSON(http.StatusOK, stats)
}

func apiFirewallGet(c *gin.Context) {
	rules := firewallpkg.List()
	c.JSON(http.StatusOK, gin.H{
		"banned_ips":       rules.BannedIPs,
		"banned_countries": rules.BannedCountries,
	})
}

func apiFirewallBanIP(c *gin.Context) {
	var req firewallIPBanRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}
	if err := firewallpkg.BanIP(ip); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func apiFirewallBanIPUpload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file"})
		return
	}
	defer f.Close()

	data := make([]byte, file.Size)
	if _, err := f.Read(data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}
	lines := strings.Split(string(data), "\n")
	var ips []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ips = append(ips, line)
	}
	added, err := firewallpkg.BanIPs(ips)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": added})
}

func apiFirewallBanCountry(c *gin.Context) {
	var req firewallCountryBanRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	var codes []string
	if len(req.Countries) > 0 {
		codes = req.Countries
	} else if strings.TrimSpace(req.Country) != "" {
		codes = []string{req.Country}
	}
	if len(codes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "country code is required"})
		return
	}
	added, err := firewallpkg.BanCountries(codes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": added})
}

func apiDomainsCreate(c *gin.Context) {
	var req createDomainRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	domain := strings.TrimSpace(req.Domain)
	target := strings.TrimSpace(req.Target)
	if domain == "" || target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain and target are required"})
		return
	}

	allowSSL := req.SSL
	allowHTTP := req.HTTP
	if !allowSSL && !allowHTTP {
		allowHTTP = true
	}

	var certPathPtr *string
	var keyPathPtr *string
	if allowSSL {
		mode := strings.ToLower(strings.TrimSpace(req.CertMode))
		if mode == "" {
			mode = "generate"
		}
		if mode == "custom" {
			cp := strings.TrimSpace(req.CertPath)
			kp := strings.TrimSpace(req.KeyPath)
			if cp == "" || kp == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "certificate and key paths are required for custom SSL"})
				return
			}
			certPathPtr = &cp
			keyPathPtr = &kp
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "automatic certificate generation is not implemented; please use Custom and provide certificate paths"})
			return
		}
	}

	cfg := filepkg.Config{
		Domain:            domain,
		Location:          target,
		AllowSSL:          allowSSL,
		AllowHTTP:         allowHTTP,
		SSLCertificate:    certPathPtr,
		SSLCertificateKey: keyPathPtr,
	}

	if err := filepkg.WriteConfig("./domains", cfg); err != nil {
		logger.SystemLog("error", "api_domains_create", fmt.Sprintf("failed to write config for '%s': %v", domain, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write domain config"})
		return
	}

	logger.SystemLog("success", "api_domains_create", fmt.Sprintf("created domain '%s' -> %s", domain, target))
	c.JSON(http.StatusOK, gin.H{"domain": cfg.Domain, "host": cfg.Location, "SSL": cfg.AllowSSL, "HTTP": cfg.AllowHTTP})
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

type createRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func apiRolesList(c *gin.Context) {
	rList := rolepkg.List()
	c.JSON(http.StatusOK, gin.H{"roles": rList})
}

func apiRolesCreate(c *gin.Context) {
	var req createRoleRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name is required"})
		return
	}
	var perms []rolepkg.Permission
	for _, p := range req.Permissions {
		perms = append(perms, rolepkg.Permission(p))
	}
	r, err := rolepkg.Create(req.Name, req.Description, perms)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.SystemLog("success", "api_roles_create", fmt.Sprintf("created role '%s'", r.Name))
	c.JSON(http.StatusOK, gin.H{"role": r})
}

func apiRolesUpdate(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name is required"})
		return
	}
	var req createRoleRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	var perms []rolepkg.Permission
	for _, p := range req.Permissions {
		perms = append(perms, rolepkg.Permission(p))
	}
	r, err := rolepkg.Update(name, req.Description, perms)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.SystemLog("success", "api_roles_update", fmt.Sprintf("updated role '%s'", r.Name))
	c.JSON(http.StatusOK, gin.H{"role": r})
}

func apiRolesDelete(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name is required"})
		return
	}
	if err := rolepkg.Delete(name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.SystemLog("success", "api_roles_delete", fmt.Sprintf("deleted role '%s'", name))
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
