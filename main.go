package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"SparkProxy/core"
	"SparkProxy/proxy"
	"SparkProxy/ui"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var mainSharedSecret = []byte(os.Getenv("AUTH_SHARED_SECRET"))

func mainVerifySharedToken(token, domain string) (username string, valid bool) {
	if len(mainSharedSecret) == 0 {
		mainSharedSecret = []byte("sparkproxy-shared-secret-change-in-production")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	expectedSig := parts[1]
	h := hmac.New(sha256.New, mainSharedSecret)
	h.Write(data)
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(sig)) {
		return "", false
	}
	parts2 := strings.Split(string(data), "|")
	if len(parts2) != 3 {
		return "", false
	}
	username = parts2[0]
	storedDomain := parts2[1]
	expiresUnix := parts2[2]
	if !strings.EqualFold(storedDomain, domain) {
		return "", false
	}
	expiresTime, err := strconv.ParseInt(expiresUnix, 10, 64)
	if err != nil {
		return "", false
	}
	if time.Now().Unix() > expiresTime {
		return "", false
	}
	return username, true
}

func isHTTPS(c *gin.Context) bool {
	return c.Request.URL.Scheme == "https" || c.GetHeader("X-Forwarded-Proto") == "https"
}

func setSessionCookie(c *gin.Context, sessionID string) {
	isSecure := isHTTPS(c)
	c.SetCookie("session", sessionID, 3600*24, "/", "", isSecure, true)
}

func clearSessionCookie(c *gin.Context) {
	c.SetCookie("session", "", -1, "/", "", true, true)
}

func setCSRFCookie(c *gin.Context, token string) {
	isSecure := isHTTPS(c)
	c.SetCookie("csrf_token", token, 3600, "/", "", isSecure, true)
}

func csrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		sid, err := c.Cookie("session")
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf: no session"})
			c.Abort()
			return
		}

		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			cookie, err := c.Cookie("csrf_token")
			if err == nil {
				token = cookie
			}
		}

		if token == "" || !core.ValidateCSRFToken(sid, token) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf: invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

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
	healthClient = &http.Client{Timeout: 1500 * time.Millisecond}
)

func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, err := c.Cookie("session")
		if err != nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		if !core.ValidateSession(sid) {
			clearSessionCookie(c)
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Set("session_id", sid)
		c.Next()
	}
}

func apiAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, err := c.Cookie("session")
		if err == nil && sid != "" && core.ValidateSession(sid) {
			c.Set("session_id", sid)
			c.Next()
			return
		}

		spAuthShared, err := c.Cookie("sp_auth_shared")
		if err == nil && spAuthShared != "" {
			domain := c.Request.Host
			if i := strings.IndexByte(domain, ':'); i > -1 {
				domain = domain[:i]
			}
			username, valid := mainVerifySharedToken(spAuthShared, domain)
			if valid {
				c.Set("session_id", spAuthShared)
				c.Set("username", username)
				c.Next()
				return
			}
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
	}
}

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

	public := r.Group("/")
	{
		public.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "login", gin.H{}) })
		public.GET("/login", func(c *gin.Context) { c.HTML(http.StatusOK, "login", gin.H{}) })
		public.POST("/login", loginPost)
		public.POST("/api/login", apiLogin)
		public.POST("/api/logout", apiLogout)
		public.GET("/auth/oauth/:provider_id", apiOAuthLogin)
		public.GET("/_auth/oauth/callback/:provider_id", apiOAuthCallback)
		public.GET("/_auth/oauth/link/:provider_id", apiOAuthLinkCallback)
	}

	dashboard := r.Group("/")
	dashboard.Use(authRequired())
	{
		dashboard.GET("/dashboard", func(c *gin.Context) { c.HTML(http.StatusOK, "dashboard", gin.H{"ActivePage": "dashboard"}) })
		dashboard.GET("/domains", func(c *gin.Context) { c.HTML(http.StatusOK, "domains", gin.H{"ActivePage": "domains"}) })
		dashboard.GET("/analytics", func(c *gin.Context) { c.HTML(http.StatusOK, "analytics", gin.H{"ActivePage": "analytics"}) })
		dashboard.GET("/logs", func(c *gin.Context) { c.HTML(http.StatusOK, "logs", gin.H{"ActivePage": "logs"}) })
		dashboard.GET("/users", func(c *gin.Context) { c.HTML(http.StatusOK, "users", gin.H{"ActivePage": "users"}) })
		dashboard.GET("/firewall", func(c *gin.Context) { c.HTML(http.StatusOK, "firewall", gin.H{"ActivePage": "firewall"}) })
		dashboard.GET("/roles", func(c *gin.Context) { c.HTML(http.StatusOK, "roles", gin.H{"ActivePage": "roles"}) })
		dashboard.GET("/sessions", func(c *gin.Context) { c.HTML(http.StatusOK, "sessions", gin.H{"ActivePage": "sessions"}) })
		dashboard.GET("/audit", func(c *gin.Context) { c.HTML(http.StatusOK, "audit", gin.H{"ActivePage": "audit"}) })
		dashboard.GET("/api-tokens", func(c *gin.Context) { c.HTML(http.StatusOK, "api-tokens", gin.H{"ActivePage": "api-tokens"}) })
		dashboard.GET("/streams", func(c *gin.Context) { c.HTML(http.StatusOK, "streams", gin.H{"ActivePage": "streams"}) })
		dashboard.GET("/sidebar", func(c *gin.Context) { c.HTML(http.StatusOK, "sidebar", gin.H{"ActivePage": ""}) })
		dashboard.GET("/identity-providers", func(c *gin.Context) {
			c.HTML(http.StatusOK, "identity-providers", gin.H{"ActivePage": "identity-providers"})
		})
		dashboard.GET("/passkeys", func(c *gin.Context) {
			c.HTML(http.StatusOK, "passkeys", gin.H{"ActivePage": "passkeys"})
		})
		dashboard.GET("/settings", func(c *gin.Context) {
			c.HTML(http.StatusOK, "settings", gin.H{"ActivePage": "settings"})
		})
		dashboard.GET("/linked-accounts", func(c *gin.Context) {
			c.HTML(http.StatusOK, "linked-accounts", gin.H{"ActivePage": "linked-accounts"})
		})
	}

	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "404", gin.H{})
	})

	apiRead := r.Group("/api")
	apiRead.GET("/identity-providers/public", apiIdentityProvidersList)
	apiRead.Use(apiAuthRequired())
	{
		apiRead.GET("/dashboard", apiDashboard)
		apiRead.GET("/firewall", apiFirewallGet)
		apiRead.GET("/proxys", apiProxys)
		apiRead.GET("/logs", apiLogs)
		apiRead.GET("/users", apiUsersList)
		apiRead.GET("/users/me", apiUsersMe)
		apiRead.GET("/roles", apiRolesList)
		apiRead.GET("/sessions", apiSessionsList)
		apiRead.GET("/audit", apiAuditList)
		apiRead.GET("/streams", apiStreamsList)
		apiRead.GET("/streams/stats", apiStreamsStats)
		apiRead.GET("/certs", apiCertsList)
		apiRead.GET("/identity-providers", apiIdentityProvidersList)
		apiRead.GET("/passkeys", apiPasskeysList)
		apiRead.GET("/settings", apiSettingsGet)
		apiRead.GET("/users/me/identity-providers", apiUserIdentityProvidersList)
	}

	apiWrite := r.Group("/api")
	apiWrite.Use(apiAuthRequired(), csrfMiddleware())
	{
		apiWrite.POST("/passkeys/register/start", apiPasskeyRegistrationStart)
		apiWrite.POST("/passkeys/register/complete", apiPasskeyRegistrationComplete)
		apiWrite.POST("/passkeys/auth/start", apiPasskeyAuthenticationStart)
		apiWrite.POST("/passkeys/auth/complete", apiPasskeyAuthenticationComplete)
		apiWrite.DELETE("/passkeys/:id", apiPasskeysDelete)
		apiWrite.POST("/streams", apiStreamsCreate)
		apiWrite.PUT("/streams/:id", apiStreamsUpdate)
		apiWrite.DELETE("/streams/:id", apiStreamsDelete)
		apiWrite.POST("/streams/:id/toggle", apiStreamsToggle)
		apiWrite.POST("/firewall/ban-ip", apiFirewallBanIP)
		apiWrite.POST("/firewall/ban-ip-upload", apiFirewallBanIPUpload)
		apiWrite.POST("/firewall/ban-country", apiFirewallBanCountry)
		apiWrite.DELETE("/firewall/ip/:ip", apiFirewallUnbanIP)
		apiWrite.DELETE("/firewall/country/:code", apiFirewallUnbanCountry)
		apiWrite.PUT("/domains/:domain/auth", apiDomainAuthUpdate)
		apiWrite.POST("/domains", apiDomainsCreate)
		apiWrite.PUT("/domains/:domain", apiDomainsUpdate)
		apiWrite.DELETE("/domains/:domain", apiDomainsDelete)
		apiWrite.POST("/users", apiUsersCreate)
		apiWrite.DELETE("/api/users/:username", apiUsersDelete)
		apiWrite.POST("/roles", apiRolesCreate)
		apiWrite.PUT("/api/roles/:name", apiRolesUpdate)
		apiWrite.DELETE("/api/roles/:name", apiRolesDelete)
		apiWrite.DELETE("/api/sessions/:id", apiSessionRevoke)
		apiWrite.DELETE("/api/sessions/user/:username", apiSessionsRevokeAll)
		apiWrite.POST("/certs/request", apiCertsRequest)
		apiWrite.POST("/certs/:domain/renew", apiCertsRenew)
		apiWrite.DELETE("/certs/:domain", apiCertsDelete)
		apiWrite.POST("/identity-providers", apiIdentityProvidersCreate)
		apiWrite.DELETE("/identity-providers/:id", apiIdentityProvidersDelete)
		apiWrite.POST("/identity-providers/:id/toggle", apiIdentityProvidersToggle)
		apiWrite.GET("/users/me/identity-providers/:provider_id/link", apiUserIdentityProviderLinkStart)
		apiWrite.DELETE("/users/me/identity-providers/:provider_id", apiUserIdentityProviderUnlink)
		apiWrite.PUT("/settings", apiSettingsUpdate)
		apiWrite.POST("/settings/reset", apiSettingsReset)
	}

	apiTokens := r.Group("/api/tokens")
	{
		apiTokens.GET("", apiTokensList)
		apiTokens.POST("", apiAuthRequired(), csrfMiddleware(), apiTokensCreate)
		apiTokens.DELETE("/:id", apiAuthRequired(), csrfMiddleware(), apiTokensRevoke)
	}

	go func() {
		cfgs := core.ReadConfigs("./domains")
		if err := proxy.StartProxy(cfgs); err != nil {
			ui.SystemLog("error", "proxy", fmt.Sprintf("Proxy error: %v", err))
		}
	}()

	go func() {
		if err := proxy.StartStreamServer(); err != nil {
			ui.SystemLog("error", "stream-server", fmt.Sprintf("Failed to start stream server: %v", err))
		}
	}()

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	ui.SystemLog("info", "dashboard", fmt.Sprintf("Started on %s", addr))
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
		core.LogAudit("user_login_failed", "unknown", c.ClientIP(), c.GetHeader("User-Agent"), "/api/login", "failed", map[string]string{"reason": "invalid payload"})
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	validUser := os.Getenv("USER")
	validPass := os.Getenv("PASSWORD")

	if req.Username == validUser && req.Password == validPass && validUser != "" && validPass != "" {
		core.RevokeSessionsByUser(req.Username)
		sid := core.CreateSession(req.Username, "Owner", ip, userAgent)
		csrfToken := core.GenerateCSRFToken(sid)
		setSessionCookie(c, sid)
		setCSRFCookie(c, csrfToken)
		core.LogAudit("user_login", req.Username, ip, userAgent, "/api/login", "success", nil)
		c.JSON(http.StatusOK, gin.H{"valid": true, "session_id": sid, "csrf_token": csrfToken})
		return
	}

	u, ok := core.AuthenticateUser(req.Username, req.Password)
	if ok && u != nil {
		role := "Member"
		if u.Role != "" {
			role = u.Role
		}
		core.RevokeSessionsByUser(u.Username)
		sid := core.CreateSession(u.Username, role, ip, userAgent)
		csrfToken := core.GenerateCSRFToken(sid)
		setSessionCookie(c, sid)
		setCSRFCookie(c, csrfToken)
		core.LogAudit("user_login", u.Username, ip, userAgent, "/api/login", "success", nil)
		c.JSON(http.StatusOK, gin.H{"valid": true, "session_id": sid, "csrf_token": csrfToken})
		return
	}

	core.LogAudit("user_login_failed", req.Username, ip, userAgent, "/api/login", "failed", map[string]string{"reason": "invalid credentials"})
	c.JSON(http.StatusOK, gin.H{"valid": false})
}

func apiProxys(c *gin.Context) {
	configs := core.ReadConfigs("./domains")
	statSlice := proxy.GetDomainStats()
	stats := make(map[string]proxy.DomainStats)
	for _, s := range statSlice {
		stats[s.Domain] = s
	}

	var cfgsOut []map[string]interface{}
	for _, cfg := range configs {
		hasCustomCert := cfg.SSLCertificate != nil && *cfg.SSLCertificate != ""
		hasCustomKey := cfg.SSLCertificateKey != nil && *cfg.SSLCertificateKey != ""

		certSource := proxy.SourceNone
		if cfg.AllowSSL {
			if hasCustomCert && hasCustomKey {
				certSource = proxy.SourceCustom
			} else if proxy.CertificateExists(cfg.Domain) {
				certSource = proxy.SourceAuto
			}
		}

		certInfo := proxy.GetCertificateInfoForDomain(cfg.Domain, cfg.SSLCertificate, cfg.SSLCertificateKey)

		m := map[string]interface{}{
			"domain":      cfg.Domain,
			"host":        cfg.Location,
			"SSL":         cfg.AllowSSL,
			"HTTP":        cfg.AllowHTTP,
			"pubkey":      cfg.SSLCertificate,
			"privkey":     cfg.SSLCertificateKey,
			"cert_source": certSource,
			"cert_status": string(certInfo.Source),
			"days_left":   certInfo.DaysLeft,
			"auto_cert":   certInfo.Source == proxy.SourceAuto,
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

		m["require_auth"] = proxy.GetDomainAuth(cfg.Domain)
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
	domainStats := proxy.GetDomainStats()
	var uploadTotal int64
	var downloadTotal int64
	for _, ds := range domainStats {
		uploadTotal += ds.DataOutTotal
		downloadTotal += ds.DataInTotal
	}

	logs := core.GetRequestLogs()
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
	rules := core.ListFirewallRules()
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
	if err := core.BanIP(ip); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("firewall_rule_add", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/firewall/ban-ip", "success", map[string]string{"type": "ip", "value": ip})
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
	added, err := core.BanIPs(ips)
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
	added, err := core.BanCountries(codes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("firewall_rule_add", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/firewall/ban-country", "success", map[string]string{"type": "country", "count": fmt.Sprintf("%d", added)})
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

	cfg := core.Config{
		Domain:            domain,
		Location:          target,
		AllowSSL:          allowSSL,
		AllowHTTP:         allowHTTP,
		SSLCertificate:    certPathPtr,
		SSLCertificateKey: keyPathPtr,
	}

	if err := core.WriteConfig("./domains", cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write domain config"})
		return
	}

	core.LogAudit("domain_create", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/domains", "success", map[string]string{"domain": domain, "target": target})
	c.JSON(http.StatusOK, gin.H{"domain": cfg.Domain, "host": cfg.Location, "SSL": cfg.AllowSSL, "HTTP": cfg.AllowHTTP})
}

type updateDomainRequest struct {
	Target   string `json:"target"`
	HTTP     bool   `json:"http"`
	SSL      bool   `json:"ssl"`
	CertMode string `json:"cert_mode"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

func apiDomainsUpdate(c *gin.Context) {
	domain := c.Param("domain")
	if strings.TrimSpace(domain) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	var req updateDomainRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
		return
	}

	var certPath, keyPath string
	if req.CertMode == "custom" {
		certPath = req.CertPath
		keyPath = req.KeyPath
	}

	err := core.UpdateDomain(domain, req.Target, req.SSL, req.HTTP, certPath, keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}
		core.LogAudit("domain_update_failed", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/domains/"+domain, "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	cfg, _ := core.GetDomainConfig(domain)
	core.LogAudit("domain_update", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/domains/"+domain, "success", map[string]string{"domain": domain, "target": req.Target})
	c.JSON(http.StatusOK, gin.H{
		"domain":  cfg.Domain,
		"host":    cfg.Location,
		"SSL":     cfg.AllowSSL,
		"HTTP":    cfg.AllowHTTP,
		"pubkey":  cfg.SSLCertificate,
		"privkey": cfg.SSLCertificateKey,
	})
}

func apiDomainsDelete(c *gin.Context) {
	domain := c.Param("domain")
	if strings.TrimSpace(domain) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	err := core.DeleteDomain(domain)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}
		core.LogAudit("domain_delete_failed", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/domains/"+domain, "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	core.LogAudit("domain_delete", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/domains/"+domain, "success", map[string]string{"domain": domain})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func apiLogs(c *gin.Context) {
	var page, limit int
	fmt.Sscanf(c.Query("page"), "%d", &page)
	fmt.Sscanf(c.Query("limit"), "%d", &limit)

	data := core.GetRequestLogsPaginated(page, limit)
	var out []map[string]interface{}
	for _, l := range data.Logs {
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
	c.JSON(http.StatusOK, gin.H{
		"logs": out,
		"pagination": gin.H{
			"page":        data.Page,
			"limit":       data.Limit,
			"total":       data.Total,
			"total_pages": data.TotalPages,
		},
	})
}

func apiUsersList(c *gin.Context) {
	users := core.ListUsers()
	var out []map[string]interface{}
	for _, u := range users {
		out = append(out, map[string]interface{}{
			"username":           u.Username,
			"email":              u.Email,
			"identity_providers": u.IdentityProviders,
			"role":               u.Role,
			"access_type":        u.AccessType,
			"domains":            u.AllowedDomainList,
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": out})
}

func apiUsersMe(c *gin.Context) {
	sid, _ := c.Get("session_id")
	if sid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	s, ok := core.GetSession(sid.(string))
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"username": s.Username,
		"role":     s.Role,
	})
}

func apiUsersCreate(c *gin.Context) {
	var req createUserRequest
	if err := c.BindJSON(&req); err != nil {
		core.LogAudit("user_create_failed", "unknown", c.ClientIP(), c.GetHeader("User-Agent"), "/api/users", "failed", map[string]string{"reason": "invalid payload"})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Role == "" {
		req.Role = "Member"
	}
	u, err := core.CreateUser(req.Username, req.Email, req.Password, req.Role, req.AccessType, req.Domains)
	if err != nil {
		core.LogAudit("user_create_failed", "unknown", c.ClientIP(), c.GetHeader("User-Agent"), "/api/users", "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("user_create", u.Username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/users", "success", map[string]string{"email": u.Email, "role": u.Role})
	c.JSON(http.StatusOK, gin.H{"user": map[string]interface{}{
		"username":           u.Username,
		"email":              u.Email,
		"identity_providers": u.IdentityProviders,
		"role":               u.Role,
		"access_type":        u.AccessType,
		"domains":            u.AllowedDomainList,
	}})
}

func apiUsersDelete(c *gin.Context) {
	username := c.Param("username")
	if err := core.DeleteUser(username); err != nil {
		core.LogAudit("user_delete_failed", username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/users/"+username, "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.RevokeSessionsByUser(username)
	core.LogAudit("user_delete", username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/users/"+username, "success", nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type createRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func apiRolesList(c *gin.Context) {
	rList := core.ListRoles()
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
	var perms []core.Permission
	for _, p := range req.Permissions {
		perms = append(perms, core.Permission(p))
	}
	r, err := core.CreateRole(req.Name, req.Description, perms)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("role_create", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/roles", "success", map[string]string{"role": r.Name})
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
	var perms []core.Permission
	for _, p := range req.Permissions {
		perms = append(perms, core.Permission(p))
	}
	r, err := core.UpdateRole(name, req.Description, perms)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("role_update", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/roles/"+name, "success", map[string]string{"role": r.Name})
	c.JSON(http.StatusOK, gin.H{"role": r})
}

func apiRolesDelete(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name is required"})
		return
	}
	if err := core.DeleteRole(name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("role_delete", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/roles/"+name, "success", map[string]string{"role": name})
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
	if err := proxy.SetDomainAuth(domain, req.RequireAuth); err != nil {
		ui.SystemLog("error", "api_domain_auth", fmt.Sprintf("failed to update auth for %s: %v", domain, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update auth"})
		return
	}
	ui.SystemLog("info", "api_domain_auth", fmt.Sprintf("domain %s auth set to %v", domain, req.RequireAuth))
	c.JSON(http.StatusOK, gin.H{"domain": domain, "require_auth": req.RequireAuth})
}

func loginPost(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	validUser := os.Getenv("USER")
	validPass := os.Getenv("PASSWORD")

	if email == validUser && password == validPass && validUser != "" && validPass != "" {
		core.RevokeSessionsByUser(email)
		sid := core.CreateSession(email, "Owner", ip, userAgent)
		csrfToken := core.GenerateCSRFToken(sid)
		setSessionCookie(c, sid)
		setCSRFCookie(c, csrfToken)
		core.LogAudit("user_login", email, ip, userAgent, "/login", "success", nil)
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "Logged in successfully, redirecting…",
			"Redirect":     "/dashboard",
		})
		return
	}

	u, ok := core.AuthenticateUser(email, password)
	if ok && u != nil {
		role := "Member"
		if u.Role != "" {
			role = u.Role
		}
		core.RevokeSessionsByUser(u.Username)
		sid := core.CreateSession(u.Username, role, ip, userAgent)
		csrfToken := core.GenerateCSRFToken(sid)
		setSessionCookie(c, sid)
		setCSRFCookie(c, csrfToken)
		core.LogAudit("user_login", u.Username, ip, userAgent, "/login", "success", nil)
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "Logged in successfully, redirecting…",
			"Redirect":     "/dashboard",
		})
		return
	}

	core.LogAudit("user_login_failed", email, ip, userAgent, "/login", "failed", map[string]string{"reason": "invalid credentials"})
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

func apiLogout(c *gin.Context) {
	sid, err := c.Cookie("session")
	if err == nil && sid != "" {
		core.RevokeSession(sid)
		core.LogAudit("user_logout", "", c.ClientIP(), c.GetHeader("User-Agent"), "/api/logout", "success", nil)
	}
	clearSessionCookie(c)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func apiSessionsList(c *gin.Context) {
	sessions := core.ListSessions()
	var out []map[string]interface{}
	for _, s := range sessions {
		out = append(out, map[string]interface{}{
			"id":          s.ID,
			"username":    s.Username,
			"role":        s.Role,
			"ip":          s.IP,
			"user_agent":  s.UserAgent,
			"created_at":  s.CreatedAt.Format(time.RFC3339),
			"last_access": s.LastAccess.Format(time.RFC3339),
			"expires_at":  s.ExpiresAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"sessions": out})
}

func apiSessionRevoke(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session id is required"})
		return
	}
	s, ok := core.GetSession(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	core.RevokeSession(id)
	core.LogAudit("session_revoke", s.Username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/sessions/"+id, "success", nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func apiSessionsRevokeAll(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}
	count := core.RevokeSessionsByUser(username)
	core.LogAudit("session_revoke", username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/sessions/user/"+username, "success", map[string]string{"count": fmt.Sprintf("%d", count)})
	c.JSON(http.StatusOK, gin.H{"ok": true, "revoked": count})
}

func apiAuditList(c *gin.Context) {
	action := c.Query("action")
	actor := c.Query("actor")
	var page, limit int
	fmt.Sscanf(c.Query("page"), "%d", &page)
	fmt.Sscanf(c.Query("limit"), "%d", &limit)

	data := core.ListAuditLogsPaginated(action, actor, page, limit)
	var out []map[string]interface{}
	for _, l := range data.Logs {
		out = append(out, map[string]interface{}{
			"id":         l.ID,
			"timestamp":  l.Timestamp.Format(time.RFC3339),
			"action":     l.Action,
			"actor":      l.Actor,
			"ip":         l.IP,
			"user_agent": l.UserAgent,
			"resource":   l.Resource,
			"status":     l.Status,
			"details":    l.Details,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"logs": out,
		"pagination": gin.H{
			"page":        data.Page,
			"limit":       data.Limit,
			"total":       data.Total,
			"total_pages": data.TotalPages,
		},
		"total":    data.Total,
		"last_24h": data.Last24h,
	})
}

func apiFirewallUnbanIP(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}
	if err := core.UnbanIP(ip); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("firewall_rule_remove", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/firewall/ip/"+ip, "success", map[string]string{"type": "ip", "value": ip})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func apiFirewallUnbanCountry(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "country code is required"})
		return
	}
	if err := core.UnbanCountry(code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	core.LogAudit("firewall_rule_remove", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/firewall/country/"+code, "success", map[string]string{"type": "country", "value": code})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type createTokenRequest struct {
	Name       string `json:"name"`
	Permission string `json:"permission"`
	Expiration int    `json:"expiration"`
}

func apiTokensList(c *gin.Context) {
	var page, limit int
	fmt.Sscanf(c.Query("page"), "%d", &page)
	fmt.Sscanf(c.Query("limit"), "%d", &limit)

	data := core.ListPublicPaginated(page, limit)
	c.JSON(http.StatusOK, gin.H{
		"tokens": data.Tokens,
		"pagination": gin.H{
			"page":        data.Page,
			"limit":       data.Limit,
			"total":       data.Total,
			"total_pages": data.TotalPages,
		},
	})
}

func apiTokensCreate(c *gin.Context) {
	var req createTokenRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.Permission != "read" && req.Permission != "write" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "permission must be read or write"})
		return
	}

	sid, _ := c.Cookie("session")
	s, _ := core.GetSession(sid)
	username := s.Username
	if username == "" {
		username = "unknown"
	}

	var expiresDays *int
	if req.Expiration > 0 {
		expiresDays = &req.Expiration
	}

	fullToken, err := core.CreateAPIToken(req.Name, req.Permission, username, expiresDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}

	core.LogAudit("token_create", username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/tokens", "success", map[string]string{"name": req.Name, "permission": req.Permission})
	c.JSON(http.StatusOK, gin.H{"token": fullToken})
}

func apiTokensRevoke(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token id is required"})
		return
	}
	if !core.RevokeAPIToken(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
		return
	}
	sid, _ := c.Cookie("session")
	s, _ := core.GetSession(sid)
	username := s.Username
	if username == "" {
		username = "unknown"
	}
	core.LogAudit("token_revoke", username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/tokens/"+id, "success", nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type createStreamRequest struct {
	Domain     string `json:"domain,omitempty"`
	ListenPort int    `json:"listen_port"`
	Upstream   string `json:"upstream"`
	TLSMode    string `json:"tls_mode,omitempty"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	Enabled    bool   `json:"enabled"`
}

func apiStreamsList(c *gin.Context) {
	streams := proxy.ListStreams()
	stats := proxy.GetStreamStats()
	c.JSON(http.StatusOK, gin.H{"streams": streams, "stats": stats})
}

func apiStreamsStats(c *gin.Context) {
	stats := proxy.GetStreamStats()
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

func apiStreamsCreate(c *gin.Context) {
	var req createStreamRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Upstream == "" || req.ListenPort == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "upstream and listen_port are required"})
		return
	}
	if req.Domain != "" {
		tlsMode := strings.ToLower(strings.TrimSpace(req.TLSMode))
		if tlsMode == "" {
			tlsMode = "pass-through"
		}
		if tlsMode != "pass-through" && tlsMode != "terminate" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tls_mode must be pass-through or terminate"})
			return
		}
	}

	streamCfg := proxy.StreamConfig{
		ID:         uuid.New().String(),
		Domain:     strings.ToLower(strings.TrimSpace(req.Domain)),
		ListenPort: req.ListenPort,
		Upstream:   strings.TrimSpace(req.Upstream),
		TLSMode:    strings.ToLower(strings.TrimSpace(req.TLSMode)),
		CertFile:   strings.TrimSpace(req.CertFile),
		KeyFile:    strings.TrimSpace(req.KeyFile),
		Enabled:    req.Enabled,
	}

	if err := proxy.CreateStream(streamCfg); err != nil {
		core.LogAudit("stream_create_failed", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams", "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create stream"})
		return
	}

	proxy.StopStreamServer()
	if err := proxy.StartStreamServer(); err != nil {
		ui.SystemLog("error", "stream-server", fmt.Sprintf("Failed to restart stream server: %v", err))
	}

	core.LogAudit("stream_create", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams", "success", map[string]string{"domain": streamCfg.Domain})
	c.JSON(http.StatusOK, gin.H{"stream": streamCfg})
}

func apiStreamsUpdate(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "stream id is required"})
		return
	}

	streams := proxy.ListStreams()
	var existing *proxy.StreamConfig
	for i := range streams {
		if streams[i].ID == id {
			existing = &streams[i]
			break
		}
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "stream not found"})
		return
	}

	var req createStreamRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	tlsMode := strings.ToLower(strings.TrimSpace(req.TLSMode))
	if tlsMode == "" {
		tlsMode = existing.TLSMode
	}
	listenPort := req.ListenPort
	if listenPort <= 0 {
		listenPort = existing.ListenPort
	}

	streamCfg := *existing
	streamCfg.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	streamCfg.ListenPort = listenPort
	streamCfg.Upstream = strings.TrimSpace(req.Upstream)
	streamCfg.TLSMode = tlsMode
	streamCfg.CertFile = strings.TrimSpace(req.CertFile)
	streamCfg.KeyFile = strings.TrimSpace(req.KeyFile)
	streamCfg.Enabled = req.Enabled

	if err := proxy.UpdateStream(id, streamCfg); err != nil {
		core.LogAudit("stream_update_failed", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams/"+id, "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update stream"})
		return
	}

	proxy.StopStreamServer()
	if err := proxy.StartStreamServer(); err != nil {
		ui.SystemLog("error", "stream-server", fmt.Sprintf("Failed to restart stream server: %v", err))
	}

	core.LogAudit("stream_update", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams/"+id, "success", map[string]string{"domain": streamCfg.Domain})
	c.JSON(http.StatusOK, gin.H{"stream": streamCfg})
}

func apiStreamsDelete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "stream id is required"})
		return
	}

	streams := proxy.ListStreams()
	var domain string
	for _, s := range streams {
		if s.ID == id {
			domain = s.Domain
			break
		}
	}

	if err := proxy.DeleteStream(id); err != nil {
		core.LogAudit("stream_delete_failed", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams/"+id, "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete stream"})
		return
	}

	proxy.StopStreamServer()
	if err := proxy.StartStreamServer(); err != nil {
		ui.SystemLog("error", "stream-server", fmt.Sprintf("Failed to restart stream server: %v", err))
	}

	core.LogAudit("stream_delete", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams/"+id, "success", map[string]string{"domain": domain})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type toggleStreamRequest struct {
	Enabled bool `json:"enabled"`
}

func apiStreamsToggle(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "stream id is required"})
		return
	}

	var req toggleStreamRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	streams := proxy.ListStreams()
	var existing *proxy.StreamConfig
	for i := range streams {
		if streams[i].ID == id {
			existing = &streams[i]
			break
		}
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "stream not found"})
		return
	}

	streamCfg := *existing
	streamCfg.Enabled = req.Enabled

	if err := proxy.UpdateStream(id, streamCfg); err != nil {
		core.LogAudit("stream_toggle_failed", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams/"+id+"/toggle", "failed", map[string]string{"reason": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to toggle stream"})
		return
	}

	proxy.StopStreamServer()
	if err := proxy.StartStreamServer(); err != nil {
		ui.SystemLog("error", "stream-server", fmt.Sprintf("Failed to restart stream server: %v", err))
	}

	core.LogAudit("stream_toggle", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/streams/"+id+"/toggle", "success", map[string]string{"domain": streamCfg.Domain, "enabled": fmt.Sprintf("%v", req.Enabled)})
	c.JSON(http.StatusOK, gin.H{"ok": true, "enabled": req.Enabled})
}

type certInfoResponse struct {
	Domain     string                  `json:"domain"`
	Source     proxy.CertificateSource `json:"source"`
	CertPath   string                  `json:"cert_path"`
	KeyPath    string                  `json:"key_path"`
	IssuerPath string                  `json:"issuer_path"`
	ExpiresAt  string                  `json:"expires_at"`
	DaysLeft   int                     `json:"days_left"`
	Provider   string                  `json:"provider,omitempty"`
}

func apiCertsList(c *gin.Context) {
	certs := proxy.ListCertificates()
	var out []certInfoResponse
	for _, cert := range certs {
		out = append(out, certInfoResponse{
			Domain:     cert.Domain,
			Source:     cert.Source,
			CertPath:   cert.CertPath,
			KeyPath:    cert.KeyPath,
			IssuerPath: cert.IssuerPath,
			ExpiresAt:  cert.ExpiresAt.Format(time.RFC3339),
			DaysLeft:   cert.DaysLeft,
			Provider:   cert.Provider,
		})
	}
	c.JSON(http.StatusOK, gin.H{"certificates": out})
}

type requestCertRequest struct {
	Domain     string `json:"domain"`
	ApiToken   string `json:"api_token"`
	UseStaging bool   `json:"use_staging"`
}

func apiCertsRequest(c *gin.Context) {
	var req requestCertRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	email := os.Getenv("ACME_EMAIL")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ACME_EMAIL environment variable not set"})
		return
	}

	apiToken := req.ApiToken
	if apiToken == "" {
		apiToken = os.Getenv("CLOUDFLARE_API_TOKEN")
	}
	if apiToken == "" {
		apiToken = os.Getenv("CLOUDFLARE_DNS_API_TOKEN")
	}

	zoneToken := os.Getenv("CLOUDFLARE_ZONE_API_TOKEN")
	apiKey := os.Getenv("CLOUDFLARE_API_KEY")
	apiEmail := os.Getenv("CLOUDFLARE_API_EMAIL")

	if apiToken == "" && zoneToken == "" && (apiKey == "" || apiEmail == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cloudflare credentials required: set CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY+CLOUDFLARE_API_EMAIL"})
		return
	}

	acmeClient, err := proxy.NewACMEClient(email, "db/certs", req.UseStaging)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create ACME client: %v", err)})
		return
	}

	if err := acmeClient.SetCloudflareProvider(apiToken, apiEmail, apiKey, zoneToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to set DNS provider: %v", err)})
		return
	}

	cert, err := acmeClient.ObtainCertificate(req.Domain)
	if err != nil {
		ui.SystemLog("error", "certs", fmt.Sprintf("Failed to obtain certificate for %s: %v", req.Domain, err))
		errMsg := err.Error()
		hint := ""
		if strings.Contains(errMsg, "zone could not be found") {
			hint = "Your Cloudflare API token cannot access this domain. Use a Global API Key (set CLOUDFLARE_API_KEY + CLOUDFLARE_API_EMAIL) or create a token with Zone:Read and DNS:Edit permissions for " + req.Domain
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to obtain certificate: %v", err),
			"hint":  hint})
		return
	}

	if err := core.UpdateDomainCertPaths(req.Domain, cert.CertPath, cert.KeyPath); err != nil {
		ui.SystemLog("warn", "certs", fmt.Sprintf("Failed to update domain config for %s: %v", req.Domain, err))
	}

	if err := proxy.ReloadCertificate(req.Domain); err != nil {
		ui.SystemLog("warn", "certs", fmt.Sprintf("Failed to reload certificate for %s: %v", req.Domain, err))
	}

	core.LogAudit("cert_request", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/certs/request", "success", map[string]string{"domain": req.Domain})
	c.JSON(http.StatusOK, gin.H{
		"certificate": cert,
		"message":     "Certificate obtained successfully",
	})
}

func apiCertsRenew(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	email := os.Getenv("ACME_EMAIL")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ACME_EMAIL environment variable not set"})
		return
	}

	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	zoneToken := os.Getenv("CLOUDFLARE_ZONE_API_TOKEN")
	apiKey := os.Getenv("CLOUDFLARE_API_KEY")
	apiEmail := os.Getenv("CLOUDFLARE_API_EMAIL")

	if apiToken == "" && zoneToken == "" && (apiKey == "" || apiEmail == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cloudflare credentials required: set CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY+CLOUDFLARE_API_EMAIL"})
		return
	}

	acmeClient, err := proxy.NewACMEClient(email, "db/certs", false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create ACME client: %v", err)})
		return
	}

	if err := acmeClient.SetCloudflareProvider(apiToken, apiEmail, apiKey, zoneToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to set DNS provider: %v", err)})
		return
	}

	cert, err := acmeClient.RenewCertificate(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to renew certificate: %v", err)})
		return
	}

	if err := core.UpdateDomainCertPaths(domain, cert.CertPath, cert.KeyPath); err != nil {
		ui.SystemLog("warn", "certs", fmt.Sprintf("Failed to update domain config for %s: %v", domain, err))
	}

	if err := proxy.ReloadCertificate(domain); err != nil {
		ui.SystemLog("warn", "certs", fmt.Sprintf("Failed to reload certificate for %s: %v", domain, err))
	}

	core.LogAudit("cert_renew", "admin", c.ClientIP(), c.GetHeader("User-Agent"), "/api/certs/"+domain+"/renew", "success", map[string]string{"domain": domain})
	c.JSON(http.StatusOK, gin.H{
		"certificate": cert,
		"message":     "Certificate renewed successfully",
	})
}

func apiCertsDelete(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	if err := proxy.RevokeCertificate(domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke certificate"})
		return
	}

	if err := proxy.ReloadCertificate(domain); err != nil {
		ui.SystemLog("warn", "certs", fmt.Sprintf("Failed to clear certificate cache for %s: %v", domain, err))
	}
}

func apiOAuthLogin(c *gin.Context) {
	providerID := c.Param("provider_id")
	if providerID == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	provider, ok := core.GetIdentityProvider(providerID)
	if !ok || !provider.Enabled {
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "OAuth provider not found or disabled",
		})
		return
	}

	state := uuid.New().String()
	c.SetCookie("oauth_state", state, 600, "/", "", isHTTPS(c), true)

	callbackURL := fmt.Sprintf("http://%s/_auth/oauth/callback/%s", c.Request.Host, providerID)
	if isHTTPS(c) {
		callbackURL = fmt.Sprintf("https://%s/_auth/oauth/callback/%s", c.Request.Host, providerID)
	}

	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=identify%%20email&state=%s",
		provider.AuthEndpoint,
		url.QueryEscape(provider.ClientID),
		url.QueryEscape(callbackURL),
		state)

	c.Redirect(http.StatusFound, authURL)
}

func apiOAuthCallback(c *gin.Context) {
	providerID := c.Param("provider_id")
	if providerID == "" {
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "OAuth callback failed: invalid provider",
		})
		return
	}

	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	if errorParam != "" {
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "OAuth authentication was cancelled or failed",
		})
		return
	}

	if code == "" || state == "" {
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "OAuth callback failed: missing parameters",
		})
		return
	}

	storedState, err := c.Cookie("oauth_state")
	if err != nil || storedState == "" || storedState != state {
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "OAuth callback failed: invalid state parameter",
		})
		return
	}

	provider, ok := core.GetIdentityProvider(providerID)
	if !ok || !provider.Enabled {
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "OAuth provider not found or disabled",
		})
		return
	}

	callbackURL := fmt.Sprintf("http://%s/_auth/oauth/callback/%s", c.Request.Host, providerID)
	if isHTTPS(c) {
		callbackURL = fmt.Sprintf("https://%s/_auth/oauth/callback/%s", c.Request.Host, providerID)
	}

	token, err := core.ExchangeOAuthCode(provider, code, callbackURL)
	if err != nil {
		ui.SystemLog("error", "oauth", fmt.Sprintf("OAuth token exchange failed: %v", err))
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "OAuth authentication failed",
		})
		return
	}

	userInfo, err := core.FetchOAuthUserInfo(provider, token.AccessToken)
	if err != nil {
		ui.SystemLog("error", "oauth", fmt.Sprintf("OAuth user info fetch failed: %v", err))
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": "Failed to get user information",
		})
		return
	}

	user, found := core.GetUserByEmailWithProvider(userInfo.Email, providerID)
	if !found {
		c.HTML(http.StatusOK, "login", gin.H{
			"ToastMessage": fmt.Sprintf("User with email %s is not registered. Please contact an administrator.", userInfo.Email),
		})
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	core.RevokeSessionsByUser(user.Username)
	role := user.Role
	if role == "" {
		role = "Member"
	}
	sid := core.CreateSession(user.Username, role, ip, userAgent)
	csrfToken := core.GenerateCSRFToken(sid)
	setSessionCookie(c, sid)
	setCSRFCookie(c, csrfToken)
	core.LogAudit("oauth_login", user.Username, ip, userAgent, "/_auth/oauth/callback/"+providerID, "success", map[string]string{"provider": provider.Name})

	c.HTML(http.StatusOK, "login", gin.H{
		"ToastMessage": "Logged in successfully, redirecting…",
		"Redirect":     "/dashboard",
	})
}

type identityProviderResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ProviderType string `json:"provider_type"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    string `json:"created_at"`
}

func apiIdentityProvidersList(c *gin.Context) {
	providers := core.ListIdentityProviders()
	var out []identityProviderResponse
	for _, p := range providers {
		out = append(out, identityProviderResponse{
			ID:           p.ID,
			Name:         p.Name,
			ProviderType: p.ProviderType,
			Enabled:      p.Enabled,
			CreatedAt:    p.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"providers": out})
}

type createIdentityProviderRequest struct {
	Name          string `json:"name"`
	ProviderType  string `json:"provider_type"`
	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	AuthEndpoint  string `json:"auth_endpoint,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
}

func apiIdentityProvidersCreate(c *gin.Context) {
	var req createIdentityProviderRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	p, err := core.CreateIdentityProvider(req.Name, req.ProviderType, req.ClientID, req.ClientSecret, req.AuthEndpoint, req.TokenEndpoint)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	callbackURL := fmt.Sprintf("%s/_auth/oauth/callback/%s", c.Request.URL.Scheme+"://"+c.Request.Host, p.ID)
	c.JSON(http.StatusOK, gin.H{
		"provider": identityProviderResponse{
			ID:           p.ID,
			Name:         p.Name,
			ProviderType: p.ProviderType,
			Enabled:      p.Enabled,
			CreatedAt:    p.CreatedAt,
		},
		"callback_url": callbackURL,
	})
}

func apiIdentityProvidersDelete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	if err := core.DeleteIdentityProvider(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type toggleIdentityProviderRequest struct {
	Enabled bool `json:"enabled"`
}

func apiIdentityProvidersToggle(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	var req toggleIdentityProviderRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if err := core.ToggleIdentityProvider(id, req.Enabled); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "enabled": req.Enabled})
}

type passkeyRegistrationResponse struct {
	Challenge   string `json:"challenge"`
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Credentials []struct {
		ID string `json:"id"`
	} `json:"credentials"`
	RP struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"rp"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	} `json:"pubKeyCredParams"`
	Timeout int `json:"timeout"`
}

func apiPasskeyRegistrationStart(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}

	if req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	userID := uuid.New().String()
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate challenge"})
		return
	}
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)

	host := c.Request.Host
	if i := strings.IndexByte(host, ':'); i > -1 {
		host = host[:i]
	}

	rpID := host
	if rpID == "" {
		rpID = "sparkproxy.local"
	}

	existingCreds := core.ListPasskeyCredentials(req.Username)
	var existingCredIDs []string
	for _, cred := range existingCreds {
		existingCredIDs = append(existingCredIDs, base64.RawURLEncoding.EncodeToString(cred.CredentialID))
	}

	resp := passkeyRegistrationResponse{
		Challenge:   challengeB64,
		UserID:      base64.RawURLEncoding.EncodeToString([]byte(userID)),
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Credentials: []struct {
			ID string `json:"id"`
		}{},
		RP: struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		}{
			Name: "SparkProxy",
			ID:   rpID,
		},
		PubKeyCredParams: []struct {
			Type string `json:"type"`
			Alg  int    `json:"alg"`
		}{
			{Type: "public-key", Alg: -7},
			{Type: "public-key", Alg: -257},
		},
		Timeout: 60000,
	}

	for _, id := range existingCredIDs {
		resp.Credentials = append(resp.Credentials, struct {
			ID string `json:"id"`
		}{ID: id})
	}

	c.JSON(http.StatusOK, gin.H{
		"response":          resp,
		"session_challenge": challengeB64,
		"session_user_id":   userID,
		"session_username":  req.Username,
	})
}

func apiPasskeyRegistrationComplete(c *gin.Context) {
	var req struct {
		Username        string `json:"username"`
		AttestationData string `json:"attestation_data"`
		Challenge       string `json:"challenge"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}

	if req.Username == "" || req.AttestationData == "" || req.Challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
		return
	}

	attestationData, err := base64.RawURLEncoding.DecodeString(req.AttestationData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid attestation data"})
		return
	}

	if len(attestationData) < 37 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid attestation format"})
		return
	}

	credIDLen := int(attestationData[16])<<8 | int(attestationData[17])
	if len(attestationData) < 37+credIDLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid attestation format"})
		return
	}

	credentialID := attestationData[18 : 18+credIDLen]
	publicKeyData := attestationData[18+credIDLen:]

	userID := uuid.New().String()
	users := core.ListUsers()
	for _, u := range users {
		if u.Username == req.Username {
			userID = u.Username
			break
		}
	}

	_, err = core.CreatePasskeyCredential(userID, req.Username, credentialID, publicKeyData, 0, "platform")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save credential"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "Passkey registered successfully"})
}

type passkeyAuthenticationRequest struct {
	Username string `json:"username"`
}

type passkeyAuthenticationResponse struct {
	Challenge   string `json:"challenge"`
	RPID        string `json:"rpId"`
	Timeout     int    `json:"timeout"`
	Credentials []struct {
		ID string `json:"id"`
	} `json:"credentials"`
	AllowCredentials []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"allowCredentials"`
}

func apiPasskeyAuthenticationStart(c *gin.Context) {
	var req passkeyAuthenticationRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate challenge"})
		return
	}
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)

	host := c.Request.Host
	if i := strings.IndexByte(host, ':'); i > -1 {
		host = host[:i]
	}

	rpID := host
	if rpID == "" {
		rpID = "sparkproxy.local"
	}

	var credentials []core.PasskeyCredential
	if req.Username != "" {
		credentials = core.ListPasskeyCredentials(req.Username)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required for passkey authentication"})
		return
	}

	var allowCredentials []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	for _, cred := range credentials {
		allowCredentials = append(allowCredentials, struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}{
			ID:   base64.RawURLEncoding.EncodeToString(cred.CredentialID),
			Type: "public-key",
		})
	}

	if len(allowCredentials) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no passkeys found for this user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"response": passkeyAuthenticationResponse{
			Challenge: challengeB64,
			RPID:      rpID,
			Timeout:   60000,
			Credentials: []struct {
				ID string `json:"id"`
			}{},
			AllowCredentials: allowCredentials,
		},
		"session_challenge": challengeB64,
		"session_username":  req.Username,
	})
}

type passkeyAuthenticationCompleteRequest struct {
	Username          string `json:"username"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
	Challenge         string `json:"challenge"`
}

func apiPasskeyAuthenticationComplete(c *gin.Context) {
	var req passkeyAuthenticationCompleteRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	if req.Username == "" || req.AuthenticatorData == "" || req.Signature == "" || req.Challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
		return
	}

	authData, err := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid authenticator data"})
		return
	}

	if len(authData) < 37 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid authenticator data format"})
		return
	}

	credentialID := authData[32:68]
	cred := core.GetPasskeyCredentialByID(credentialID)
	if cred == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}

	signCount := uint32(authData[33]) | uint32(authData[34])<<8 | uint32(authData[35])<<16 | uint32(authData[36])<<24
	if signCount > cred.SignCount {
		if err := core.UpdatePasskeySignCount(credentialID, signCount); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update sign count"})
			return
		}
	} else if signCount < cred.SignCount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid signature counter"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "username": cred.Username})
}

func apiPasskeysList(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}
	creds := core.ListPasskeyCredentials(username)
	var out []map[string]interface{}
	for _, cred := range creds {
		out = append(out, map[string]interface{}{
			"id":          cred.ID,
			"username":    cred.Username,
			"device_type": cred.DeviceType,
			"created_at":  cred.CreatedAt,
			"last_used":   cred.LastUsedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"credentials": out})
}

func apiPasskeysDelete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	if err := core.DeletePasskeyCredential(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type settingsResponse struct {
	Settings map[string]interface{} `json:"settings"`
}

func apiSettingsGet(c *gin.Context) {
	settings := map[string]interface{}{
		"addr":                      os.Getenv("ADDR"),
		"session_hours":             os.Getenv("SESSION_HOURS"),
		"log_level":                 os.Getenv("LOG_LEVEL"),
		"debug_mode":                os.Getenv("DEBUG_MODE"),
		"auth_shared_secret":        os.Getenv("AUTH_SHARED_SECRET"),
		"default_user":              os.Getenv("USER"),
		"default_password":          os.Getenv("PASSWORD"),
		"allow_basic_auth":          os.Getenv("ALLOW_BASIC_AUTH"),
		"acme_email":                os.Getenv("ACME_EMAIL"),
		"acme_staging":              os.Getenv("ACME_STAGING"),
		"cloudflare_api_token":      os.Getenv("CLOUDFLARE_API_TOKEN"),
		"cloudflare_zone_api_token": os.Getenv("CLOUDFLARE_ZONE_API_TOKEN"),
		"cloudflare_api_key":        os.Getenv("CLOUDFLARE_API_KEY"),
		"cloudflare_api_email":      os.Getenv("CLOUDFLARE_API_EMAIL"),
		"geoip_db_path":             os.Getenv("GEOIP_DB_PATH"),
	}
	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

func apiSettingsUpdate(c *gin.Context) {
	var updates map[string]interface{}
	if err := c.BindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	envKeys := map[string]string{
		"addr":                      "ADDR",
		"session_hours":             "SESSION_HOURS",
		"log_level":                 "LOG_LEVEL",
		"debug_mode":                "DEBUG_MODE",
		"auth_shared_secret":        "AUTH_SHARED_SECRET",
		"default_user":              "USER",
		"default_password":          "PASSWORD",
		"allow_basic_auth":          "ALLOW_BASIC_AUTH",
		"acme_email":                "ACME_EMAIL",
		"acme_staging":              "ACME_STAGING",
		"cloudflare_api_token":      "CLOUDFLARE_API_TOKEN",
		"cloudflare_zone_api_token": "CLOUDFLARE_ZONE_API_TOKEN",
		"cloudflare_api_key":        "CLOUDFLARE_API_KEY",
		"cloudflare_api_email":      "CLOUDFLARE_API_EMAIL",
		"geoip_db_path":             "GEOIP_DB_PATH",
	}

	for key, envKey := range envKeys {
		if val, ok := updates[key]; ok {
			if s, ok := val.(string); ok {
				if s == "" {
					os.Unsetenv(envKey)
				} else {
					os.Setenv(envKey, s)
				}
			} else if b, ok := val.(bool); ok {
				if b {
					os.Setenv(envKey, "true")
				} else {
					os.Unsetenv(envKey)
				}
			} else if n, ok := val.(float64); ok {
				os.Setenv(envKey, fmt.Sprintf("%d", int(n)))
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func apiSettingsReset(c *gin.Context) {
	envVars := []string{
		"ADDR", "SESSION_HOURS", "LOG_LEVEL", "DEBUG_MODE",
		"AUTH_SHARED_SECRET", "USER", "PASSWORD", "ALLOW_BASIC_AUTH",
		"ACME_EMAIL", "ACME_STAGING",
		"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_API_EMAIL",
		"GEOIP_DB_PATH",
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}
	apiSettingsGet(c)
}

func apiUserIdentityProvidersList(c *gin.Context) {
	sid, _ := c.Get("session_id")
	if sid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	s, ok := core.GetSession(sid.(string))
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}

	linkedProviders := core.GetUserLinkedProviders(s.Username)
	c.JSON(http.StatusOK, gin.H{"providers": linkedProviders})
}

func apiUserIdentityProviderLinkStart(c *gin.Context) {
	sid, _ := c.Get("session_id")
	if sid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	s, ok := core.GetSession(sid.(string))
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}

	providerID := c.Param("provider_id")
	if providerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_id is required"})
		return
	}

	provider, ok := core.GetIdentityProvider(providerID)
	if !ok || !provider.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider not found or disabled"})
		return
	}

	if core.IsProviderLinkedToUser(s.Username, providerID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider already linked"})
		return
	}

	linkState := fmt.Sprintf("%s:%s", sid.(string), uuid.New().String())
	c.SetCookie("link_state", linkState, 600, "/", "", isHTTPS(c), true)

	callbackURL := fmt.Sprintf("http://%s/_auth/oauth/link/%s", c.Request.Host, providerID)
	if isHTTPS(c) {
		callbackURL = fmt.Sprintf("https://%s/_auth/oauth/link/%s", c.Request.Host, providerID)
	}

	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=identify%%20email&state=%s",
		provider.AuthEndpoint,
		url.QueryEscape(provider.ClientID),
		url.QueryEscape(callbackURL),
		url.QueryEscape(linkState))

	c.Redirect(http.StatusFound, authURL)
}

func apiUserIdentityProviderUnlink(c *gin.Context) {
	sid, _ := c.Get("session_id")
	if sid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	s, ok := core.GetSession(sid.(string))
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}

	providerID := c.Param("provider_id")
	if providerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_id is required"})
		return
	}

	err := core.UnlinkIdentityProviderFromUser(s.Username, providerID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	core.LogAudit("identity_provider_unlink", s.Username, c.ClientIP(), c.GetHeader("User-Agent"), "/api/users/me/identity-providers/"+providerID, "success", map[string]string{"provider_id": providerID})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func apiOAuthLinkCallback(c *gin.Context) {
	providerID := c.Param("provider_id")
	if providerID == "" {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth link failed: invalid provider",
		})
		return
	}

	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	if errorParam != "" {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth linking was cancelled or failed",
		})
		return
	}

	if code == "" || state == "" {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth link failed: missing parameters",
		})
		return
	}

	linkState, err := c.Cookie("link_state")
	if err != nil || linkState == "" {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth link failed: invalid link state",
		})
		return
	}

	parts := strings.SplitN(linkState, ":", 2)
	if len(parts) != 2 {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth link failed: invalid link state format",
		})
		return
	}

	sessionID := parts[0]
	storedState := parts[1]

	if storedState != state {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth link failed: state mismatch",
		})
		return
	}

	s, ok := core.GetSession(sessionID)
	if !ok {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth link failed: session not found",
		})
		return
	}

	provider, ok := core.GetIdentityProvider(providerID)
	if !ok || !provider.Enabled {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "Provider not found or disabled",
		})
		return
	}

	callbackURL := fmt.Sprintf("http://%s/_auth/oauth/link/%s", c.Request.Host, providerID)
	if isHTTPS(c) {
		callbackURL = fmt.Sprintf("https://%s/_auth/oauth/link/%s", c.Request.Host, providerID)
	}

	token, err := core.ExchangeOAuthCode(provider, code, callbackURL)
	if err != nil {
		ui.SystemLog("error", "oauth-link", fmt.Sprintf("OAuth token exchange failed: %v", err))
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "OAuth linking failed",
		})
		return
	}

	userInfo, err := core.FetchOAuthUserInfo(provider, token.AccessToken)
	if err != nil {
		ui.SystemLog("error", "oauth-link", fmt.Sprintf("OAuth user info fetch failed: %v", err))
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": "Failed to get user information",
		})
		return
	}

	err = core.LinkIdentityProviderToUser(s.Username, provider, userInfo.Email)
	if err != nil {
		c.HTML(http.StatusOK, "linked-accounts", gin.H{
			"ActivePage":   "linked-accounts",
			"ToastMessage": err.Error(),
		})
		return
	}

	core.LogAudit("identity_provider_link", s.Username, c.ClientIP(), c.GetHeader("User-Agent"), "/_auth/oauth/link/"+providerID, "success", map[string]string{"provider": provider.Name, "email": userInfo.Email})

	c.HTML(http.StatusOK, "linked-accounts", gin.H{
		"ActivePage":   "linked-accounts",
		"ToastMessage": fmt.Sprintf("Successfully linked %s account", provider.Name),
		"Redirect":     "/linked-accounts",
	})
}
