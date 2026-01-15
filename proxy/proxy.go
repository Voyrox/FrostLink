package proxy

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SparkProxy/core"
	"SparkProxy/ui"

	"github.com/google/uuid"
	"github.com/oschwald/geoip2-golang"
)

type domainStats struct {
	Domain        string
	DataInTotal   int64
	DataOutTotal  int64
	TotalRequests int64
	LastIP        string
	LastCountry   string
	LastPath      string
}

type DomainStats struct {
	Domain        string `json:"domain"`
	DataInTotal   int64  `json:"data_in_total"`
	DataOutTotal  int64  `json:"data_out_total"`
	TotalRequests int64  `json:"total_requests"`
	LastIP        string `json:"last_ip"`
	LastCountry   string `json:"last_country"`
	LastPath      string `json:"last_path"`
}

var (
	statsMu      sync.Mutex
	domainStatsM = make(map[string]*domainStats)
	geoDBOnce    sync.Once
	geoDB        *geoip2.Reader

	cidrOnce sync.Once
	ipv4CIDR []ipRange
	ipv6CIDR []ipRange

	indexTplOnce sync.Once
	indexTpl     *template.Template
)

type ipRange struct {
	network *net.IPNet
	country string
}

func clientIP(r *stdhttp.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func initGeoDB() {
	path := os.Getenv("GEOIP_DB_PATH")
	if path == "" {
		return
	}
	db, err := geoip2.Open(path)
	if err != nil {
		ui.SystemLog("error", "geoip", fmt.Sprintf("Failed to open GeoIP DB %s: %v", path, err))
		return
	}
	geoDB = db
}

func lookupCountry(ip string) string {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return "UNKNOWN"
	}

	if country := lookupCountryGeoIP(netIP); country != "" {
		return country
	}
	if country := lookupCountryCIDR(netIP); country != "" {
		return country
	}
	return "UNKNOWN"
}

func lookupCountryGeoIP(netIP net.IP) string {
	geoDBOnce.Do(initGeoDB)
	if geoDB == nil {
		return "UNKNOWN"
	}
	rec, err := geoDB.Country(netIP)
	if err != nil || rec == nil {
		return "UNKNOWN"
	}
	if rec.Country.IsoCode != "" {
		return rec.Country.IsoCode
	}
	if name, ok := rec.Country.Names["en"]; ok && name != "" {
		return name
	}
	return "UNKNOWN"
}

func initCIDRDB() {
	loadCIDRFile("./db/IPV4.CIDR.CSV", true)
	loadCIDRFile("./db/IPV6.CIDR.CSV", false)
}

func loadCIDRFile(path string, isIPv4 bool) {
	f, err := os.Open(path)
	if err != nil {
		ui.SystemLog("error", "cidrdb", fmt.Sprintf("Failed to open CIDR DB %s: %v", path, err))
		return
	}
	defer f.Close()

	r := csv.NewReader(f)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			ui.SystemLog("error", "cidrdb", fmt.Sprintf("Error reading CIDR DB %s: %v", path, err))
			break
		}
		if len(rec) < 2 {
			continue
		}
		cidr := rec[0]
		country := rec[1]
		_, network, err := net.ParseCIDR(strings.TrimSpace(strings.Trim(cidr, "\"")))
		if err != nil {
			continue
		}
		ir := ipRange{network: network, country: strings.TrimSpace(strings.Trim(country, "\""))}
		if isIPv4 {
			ipv4CIDR = append(ipv4CIDR, ir)
		} else {
			ipv6CIDR = append(ipv6CIDR, ir)
		}
	}
}

func lookupCountryCIDR(netIP net.IP) string {
	cidrOnce.Do(initCIDRDB)
	if len(ipv4CIDR) == 0 && len(ipv6CIDR) == 0 {
		return ""
	}
	isIPv4 := netIP.To4() != nil
	if isIPv4 {
		for _, r := range ipv4CIDR {
			if r.network.Contains(netIP) && r.country != "" {
				return r.country
			}
		}
	} else {
		for _, r := range ipv6CIDR {
			if r.network.Contains(netIP) && r.country != "" {
				return r.country
			}
		}
	}
	return ""
}

type loggingResponseWriter struct {
	stdhttp.ResponseWriter
	bytesWritten int64
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytesWritten += int64(n)
	return n, err
}

func logRequestStats(cfg core.Config, r *stdhttp.Request, bytesIn, bytesOut int64) {
	ip := clientIP(r)
	country := lookupCountry(ip)
	domain := cfg.Domain
	path := r.URL.Path
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}

	statsMu.Lock()
	ds, ok := domainStatsM[domain]
	if !ok {
		ds = &domainStats{Domain: domain}
		domainStatsM[domain] = ds
	}
	ds.DataInTotal += bytesIn
	ds.DataOutTotal += bytesOut
	ds.TotalRequests++
	ds.LastIP = ip
	ds.LastCountry = country
	ds.LastPath = path
	currentTotal := ds.TotalRequests
	totalIn := ds.DataInTotal
	totalOut := ds.DataOutTotal
	statsMu.Unlock()

	core.LogRequest("Allow", ip, country, domain, path, r.Method)

	debugLog := os.Getenv("DEBUG")
	if debugLog == "true" {
		ui.SystemLog("info", "proxy-request",
			fmt.Sprintf("proto=%s domain=%s ip=%s country=%s path=%s data_in=%d data_out=%d total_requests=%d total_in=%d total_out=%d",
				proto, domain, ip, country, path, bytesIn, bytesOut, currentTotal, totalIn, totalOut))
	}
}

func logBlockedRequest(host, ip, country string, r *stdhttp.Request, reason string) {
	if reason == "" {
		reason = "blocked"
	}
	core.LogRequest(reason, ip, country, host, r.URL.Path, r.Method)

	debugLog := os.Getenv("DEBUG")
	if debugLog == "true" {
		ui.SystemLog("info", "proxy-firewall-block",
			fmt.Sprintf("host=%s ip=%s country=%s path=%s reason=%s", host, ip, country, r.URL.Path, reason))
	}
}

func GetDomainStats() []DomainStats {
	statsMu.Lock()
	defer statsMu.Unlock()

	res := make([]DomainStats, 0, len(domainStatsM))
	for _, ds := range domainStatsM {
		res = append(res, DomainStats{
			Domain:        ds.Domain,
			DataInTotal:   ds.DataInTotal,
			DataOutTotal:  ds.DataOutTotal,
			TotalRequests: ds.TotalRequests,
			LastIP:        ds.LastIP,
			LastCountry:   ds.LastCountry,
			LastPath:      ds.LastPath,
		})
	}
	return res
}

func StartProxy(configs []core.Config) error {
	addr := os.Getenv("PROXY_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ip := clientIP(r)
		country := lookupCountry(ip)
		if core.IsBlocked(ip, country) {
			logBlockedRequest(r.Host, ip, country, r, "firewall-block")
			w.WriteHeader(stdhttp.StatusForbidden)
			_, _ = w.Write([]byte("Access blocked by firewall"))
			return
		}

		if strings.HasPrefix(r.URL.Path, "/_auth/") {
			handleAuthRoutes(w, r)
			return
		}

		host := r.Host
		cfg, ok := findConfigByHost(configs, host)
		if !ok {
			serveIndexPage(w, r)
			return
		}
		if !cfg.AllowHTTP {
			w.WriteHeader(stdhttp.StatusForbidden)
			_, _ = w.Write([]byte("HTTP disabled for this domain"))
			return
		}

		if GetDomainAuth(cfg.Domain) && !isAuthorizedForDomain(cfg.Domain, r) {
			redirectToAuthLogin(w, r, cfg)
			return
		}

		upstream := cfg.Location
		if upstream == "" {
			w.WriteHeader(stdhttp.StatusBadGateway)
			_, _ = w.Write([]byte("Upstream not configured"))
			return
		}

		targetURL, err := url.Parse("http://" + strings.TrimSpace(upstream))
		if err != nil {
			w.WriteHeader(stdhttp.StatusBadGateway)
			_, _ = w.Write([]byte("Invalid upstream: " + err.Error()))
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}

		lrw := &loggingResponseWriter{ResponseWriter: w}
		var bytesIn int64
		if r.ContentLength > 0 {
			bytesIn = r.ContentLength
		}

		proxy.Director = func(req *stdhttp.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		proxy.ErrorHandler = func(w stdhttp.ResponseWriter, req *stdhttp.Request, e error) {
			w.WriteHeader(stdhttp.StatusBadGateway)
			_, _ = w.Write([]byte("Proxy error: " + e.Error()))
		}

		proxy.ServeHTTP(lrw, r)
		logRequestStats(cfg, r, bytesIn, lrw.bytesWritten)
	})

	ui.SystemLog("info", "http-proxy", fmt.Sprintf("Listening on %s", addr))
	go StartTLSProxy(configs, mux)
	return stdhttp.ListenAndServe(addr, mux)
}

func findConfigByHost(configs []core.Config, host string) (core.Config, bool) {
	name := host
	if i := strings.IndexByte(name, ':'); i > -1 {
		name = name[:i]
	}
	for _, c := range configs {
		if strings.EqualFold(c.Domain, name) {
			return c, true
		}
	}
	return core.Config{}, false
}

func serveIndexPage(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	indexTplOnce.Do(func() {
		var err error
		indexTpl, err = template.ParseFiles("./views/index.tmpl")
		if err != nil {
			ui.SystemLog("error", "http-index", fmt.Sprintf("Failed to parse index.tmpl: %v", err))
		}
	})

	if indexTpl == nil {
		w.WriteHeader(stdhttp.StatusNotFound)
		_, _ = w.Write([]byte("<html><body><h1>404 Not Found</h1></body></html>"))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTpl.ExecuteTemplate(w, "index", nil); err != nil {
		ui.SystemLog("error", "http-index", fmt.Sprintf("Failed to execute index.tmpl: %v", err))
	}
}

type authConfigEntry struct {
	Domain      string `json:"domain"`
	RequireAuth bool   `json:"require_auth"`
}

type authConfigFile struct {
	Domains []authConfigEntry `json:"domains"`
}

var (
	authCfgOnce sync.Once
	authCfgMu   sync.RWMutex
	domainAuth  map[string]bool

	authCfgPath = filepath.Join(".", "db", "domain_auth.json")

	authSessionsMu sync.RWMutex
	authSessions   = make(map[string]authSession)
)

type authSession struct {
	Domain  string    `json:"domain"`
	Expires time.Time `json:"expires"`
}

func loadDomainAuth() {
	authCfgOnce.Do(func() {
		authCfgMu.Lock()
		defer authCfgMu.Unlock()

		domainAuth = make(map[string]bool)

		b, err := os.ReadFile(authCfgPath)
		if err != nil {
			return
		}
		var f authConfigFile
		if err := json.Unmarshal(b, &f); err != nil {
			return
		}
		for _, e := range f.Domains {
			if e.Domain == "" {
				continue
			}
			domainAuth[strings.ToLower(strings.TrimSpace(e.Domain))] = e.RequireAuth
		}
	})
}

func GetDomainAuth(domain string) bool {
	loadDomainAuth()
	authCfgMu.RLock()
	defer authCfgMu.RUnlock()
	if domainAuth == nil {
		return false
	}
	return domainAuth[strings.ToLower(strings.TrimSpace(domain))]
}

func SetDomainAuth(domain string, require bool) error {
	loadDomainAuth()
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return fmt.Errorf("domain is required")
	}

	authCfgMu.Lock()
	defer authCfgMu.Unlock()
	if domainAuth == nil {
		domainAuth = make(map[string]bool)
	}
	domainAuth[d] = require

	var f authConfigFile
	for dom, v := range domainAuth {
		f.Domains = append(f.Domains, authConfigEntry{Domain: dom, RequireAuth: v})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(authCfgPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(authCfgPath, data, 0600)
}

func isAuthorizedForDomain(domain string, r *stdhttp.Request) bool {
	cookie, err := r.Cookie("sp_auth")
	if err != nil || cookie == nil || cookie.Value == "" {
		return false
	}
	token := cookie.Value
	now := time.Now()

	authSessionsMu.RLock()
	s, ok := authSessions[token]
	authSessionsMu.RUnlock()
	if !ok {
		return false
	}
	if !strings.EqualFold(s.Domain, strings.TrimSpace(domain)) {
		return false
	}
	if now.After(s.Expires) {
		authSessionsMu.Lock()
		delete(authSessions, token)
		authSessionsMu.Unlock()
		return false
	}
	return true
}

func redirectToAuthLogin(w stdhttp.ResponseWriter, r *stdhttp.Request, cfg core.Config) {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	orig := &url.URL{
		Scheme:   proto,
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	redirect := orig.String()
	loginURL := &url.URL{
		Scheme: proto,
		Host:   r.Host,
		Path:   "/_auth/login",
		RawQuery: url.Values{
			"domain":   []string{cfg.Domain},
			"redirect": []string{redirect},
		}.Encode(),
	}
	stdhttp.Redirect(w, r, loginURL.String(), stdhttp.StatusFound)
}

func handleAuthRoutes(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.URL.Path != "/_auth/login" {
		stdhttp.NotFound(w, r)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}

	switch r.Method {
	case stdhttp.MethodGet:
		renderAuthLoginPage(w, domain, redirect, "")
	case stdhttp.MethodPost:
		if err := r.ParseForm(); err != nil {
			renderAuthLoginPage(w, domain, redirect, "Invalid form data")
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := strings.TrimSpace(r.FormValue("password"))
		if username == "" || password == "" {
			renderAuthLoginPage(w, domain, redirect, "Username and password are required")
			return
		}

		ok, err := verifyCredentialsWithAPI(username, password)
		if err != nil {
			ui.SystemLog("error", "domain-auth", fmt.Sprintf("auth API error for domain %s: %v", domain, err))
			renderAuthLoginPage(w, domain, redirect, "Authentication service error. Please try again.")
			return
		}
		if !ok {
			renderAuthLoginPage(w, domain, redirect, "Invalid credentials")
			return
		}

		token := uuid.NewString()
		expires := time.Now().Add(24 * time.Hour)
		authSessionsMu.Lock()
		authSessions[token] = authSession{Domain: strings.ToLower(domain), Expires: expires}
		authSessionsMu.Unlock()

		cookie := &stdhttp.Cookie{
			Name:     "sp_auth",
			Value:    token,
			Path:     "/",
			Expires:  expires,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: stdhttp.SameSiteLaxMode,
		}
		stdhttp.SetCookie(w, cookie)

		stdhttp.Redirect(w, r, redirect, stdhttp.StatusFound)
	default:
		w.WriteHeader(stdhttp.StatusMethodNotAllowed)
	}
}

func verifyCredentialsWithAPI(username, password string) (bool, error) {
	baseURL := os.Getenv("AUTH_API_URL")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8080"
	}
	authURL, err := url.Parse(baseURL)
	if err != nil {
		return false, fmt.Errorf("invalid AUTH_API_URL: %w", err)
	}
	authURL.Path = strings.TrimRight(authURL.Path, "/") + "/api/login"

	payload := map[string]string{
		"username": username,
		"password": password,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	resp, err := stdhttp.Post(authURL.String(), "application/json", strings.NewReader(string(data)))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Valid, nil
}

var authLoginTpl = template.Must(template.New("domain-auth-login").Parse(`<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Authentication required</title>
	<style>
		body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:radial-gradient(1200px 800px at 70% -10%, rgba(34, 211, 238, .08), transparent 60%), radial-gradient(1000px 600px at 10% 120%, rgba(125, 211, 252, .06), transparent 60%), #0a0a0f; color:#e5e7eb; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; overflow:hidden; }
        .card { background:#101018;border:1px solid #1f2937;border-radius:12px;padding:24px;max-width:360px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,0.6); }
        h1 { margin-top:0;font-size:1.4rem;margin-bottom:4px; }
        p { margin-top:0;margin-bottom:16px;color:#9ca3af;font-size:.95rem; }
        label { display:block;font-size:.9rem;margin-bottom:4px;color:#e5e7eb; }
        input { width:100%;padding:8px 10px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;margin-bottom:10px;box-sizing:border-box; }
        .btn { width:100%;padding:9px 10px;border-radius:8px;border:1px solid #fe8032;background:#fe8032;color:#022c22;font-weight:600;cursor:pointer; }
        .btn:hover { background:#f38a48; }
        .error { background:#7f1d1d;color:#fecaca;padding:8px 10px;border-radius:8px;font-size:.85rem;margin-bottom:10px; }
        .meta { font-size:.8rem;color:#6b7280;margin-top:8px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Authentication required</h1>
        <p>Sign in to access <strong>{{ .Domain }}</strong>.</p>
        {{ if .Error }}<div class="error">{{ .Error }}</div>{{ end }}
        <form method="post">
            <label for="username">Username or email</label>
            <input id="username" name="username" type="text" autocomplete="username" required />
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required />
            <button class="btn" type="submit">Continue</button>
        </form>
        <div class="meta">Access will be remembered on this device for 24 hours.</div>
    </div>
</body>
</html>`))

func renderAuthLoginPage(w stdhttp.ResponseWriter, domain, redirect, errMsg string) {
	data := struct {
		Domain   string
		Redirect string
		Error    string
	}{
		Domain:   domain,
		Redirect: redirect,
		Error:    errMsg,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := authLoginTpl.Execute(w, data); err != nil {
		ui.SystemLog("error", "domain-auth", fmt.Sprintf("failed to render auth login page: %v", err))
		w.WriteHeader(stdhttp.StatusInternalServerError)
		_, _ = w.Write([]byte("Authentication page error"))
	}
}
