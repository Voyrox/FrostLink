package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"strconv"
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

type domainAnalytics struct {
	Domain          string
	Methods         map[string]int64
	Paths           map[string]int64
	IPs             map[string]int64
	ResponseCodes   map[int]int64
	HourlyRequests  [24]int64
	SlowestRequests []slowestRequest
}

type slowestRequest struct {
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	IP        string    `json:"ip"`
	Duration  int64     `json:"duration_ms"`
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

type DomainAnalytics struct {
	Domain          string           `json:"domain"`
	Methods         map[string]int64 `json:"methods"`
	Paths           []pathCount      `json:"paths"`
	IPs             []ipCount        `json:"ips"`
	ResponseCodes   map[string]int64 `json:"response_codes"`
	HourlyRequests  [24]int64        `json:"hourly_requests"`
	SlowestRequests []slowestRequest `json:"slowest_requests,omitempty"`
}

type pathCount struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

type ipCount struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

var (
	statsMu          sync.Mutex
	domainStatsM     = make(map[string]*domainStats)
	analyticsMu      sync.Mutex
	domainAnalyticsM = make(map[string]*domainAnalytics)
	geoDBOnce        sync.Once
	geoDB            *geoip2.Reader

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
	statusCode   int
	wroteHeader  bool
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytesWritten += int64(n)
	return n, err
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	if !lrw.wroteHeader {
		lrw.statusCode = code
		lrw.wroteHeader = true
	}
	lrw.ResponseWriter.WriteHeader(code)
}

func logRequestStats(cfg core.Config, r *stdhttp.Request, bytesIn, bytesOut int64, statusCode int, duration time.Duration) {
	ip := clientIP(r)
	country := lookupCountry(ip)
	domain := cfg.Domain
	path := r.URL.Path
	method := r.Method
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	hour := time.Now().Hour()

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

	analyticsMu.Lock()
	da, ok := domainAnalyticsM[domain]
	if !ok {
		da = &domainAnalytics{
			Domain:        domain,
			Methods:       make(map[string]int64),
			Paths:         make(map[string]int64),
			IPs:           make(map[string]int64),
			ResponseCodes: make(map[int]int64),
		}
		domainAnalyticsM[domain] = da
	}

	da.Methods[method]++
	da.Paths[path]++
	da.IPs[ip]++
	da.ResponseCodes[statusCode]++
	da.HourlyRequests[hour]++

	if IsProfilerEnabled(domain) {
		slowReq := slowestRequest{
			Timestamp: time.Now(),
			Path:      path,
			Method:    method,
			IP:        ip,
			Duration:  duration.Milliseconds(),
		}
		da.SlowestRequests = append([]slowestRequest{slowReq}, da.SlowestRequests...)
		if len(da.SlowestRequests) > 50 {
			da.SlowestRequests = da.SlowestRequests[:50]
		}
	}
	analyticsMu.Unlock()

	core.LogRequest("Allow", ip, country, domain, path, method)

	debugLog := os.Getenv("DEBUG")
	if debugLog == "true" {
		ui.SystemLog("info", "proxy-request",
			fmt.Sprintf("proto=%s domain=%s ip=%s country=%s path=%s method=%s status=%d data_in=%d data_out=%d total_requests=%d total_in=%d total_out=%d duration=%dms",
				proto, domain, ip, country, path, method, statusCode, bytesIn, bytesOut, currentTotal, totalIn, totalOut, duration.Milliseconds()))
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

func GetDomainAnalytics(domain string) *DomainAnalytics {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()

	da, ok := domainAnalyticsM[domain]
	if !ok {
		return &DomainAnalytics{
			Domain:         domain,
			Methods:        make(map[string]int64),
			Paths:          []pathCount{},
			IPs:            []ipCount{},
			ResponseCodes:  make(map[string]int64),
			HourlyRequests: [24]int64{},
		}
	}

	paths := make([]pathCount, 0, len(da.Paths))
	for p, c := range da.Paths {
		paths = append(paths, pathCount{Path: p, Count: c})
	}
	for i := 0; i < len(paths)-1; i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j].Count > paths[i].Count {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}
	if len(paths) > 20 {
		paths = paths[:20]
	}

	ips := make([]ipCount, 0, len(da.IPs))
	for ip, c := range da.IPs {
		country := lookupCountry(ip)
		ips = append(ips, ipCount{IP: ip, Country: country, Count: c})
	}
	for i := 0; i < len(ips)-1; i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[j].Count > ips[i].Count {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}
	if len(ips) > 20 {
		ips = ips[:20]
	}

	responseCodes := make(map[string]int64)
	for code, count := range da.ResponseCodes {
		responseCodes[itoa(code)] = count
	}

	slowest := make([]slowestRequest, len(da.SlowestRequests))
	copy(slowest, da.SlowestRequests)

	return &DomainAnalytics{
		Domain:          da.Domain,
		Methods:         da.Methods,
		Paths:           paths,
		IPs:             ips,
		ResponseCodes:   responseCodes,
		HourlyRequests:  da.HourlyRequests,
		SlowestRequests: slowest,
	}
}

func itoa(i int) string {
	return string(rune('0'+i/1000%10)) + string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
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

		start := time.Now()
		proxy.ServeHTTP(lrw, r)
		duration := time.Since(start)

		statusCode := lrw.statusCode
		if statusCode == 0 {
			statusCode = 200
		}

		logRequestStats(cfg, r, bytesIn, lrw.bytesWritten, statusCode, duration)
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

	sharedSecret = []byte(os.Getenv("AUTH_SHARED_SECRET"))
)

type authSession struct {
	Domain  string    `json:"domain"`
	Expires time.Time `json:"expires"`
}

func generateSharedToken(username, domain string, expires time.Time) string {
	if len(sharedSecret) == 0 {
		sharedSecret = []byte("sparkproxy-shared-secret-change-in-production")
	}
	data := fmt.Sprintf("%s|%s|%d", username, domain, expires.Unix())
	h := hmac.New(sha256.New, sharedSecret)
	h.Write([]byte(data))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	token := base64.RawURLEncoding.EncodeToString([]byte(data)) + "." + sig
	return token
}

func verifySharedToken(token, domain string) (username string, valid bool) {
	if len(sharedSecret) == 0 {
		sharedSecret = []byte("sparkproxy-shared-secret-change-in-production")
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
	h := hmac.New(sha256.New, sharedSecret)
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
	path := r.URL.Path

	if strings.HasPrefix(path, "/_auth/passkey/register/") {
		handlePasskeyRegistration(w, r)
		return
	}

	if strings.HasPrefix(path, "/_auth/passkey/auth/") {
		handlePasskeyAuthentication(w, r)
		return
	}

	if strings.HasPrefix(path, "/_auth/passkeys/check/") {
		username := strings.TrimPrefix(path, "/_auth/passkeys/check/")
		handlePasskeyCheck(w, username)
		return
	}

	if path != "/_auth/login" {
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

		domain = strings.TrimSpace(r.FormValue("domain"))
		if domain == "" {
			domain = strings.TrimSpace(r.URL.Query().Get("domain"))
		}
		redirect = strings.TrimSpace(r.FormValue("redirect"))
		if redirect == "" {
			redirect = r.URL.Query().Get("redirect")
		}
		if redirect == "" {
			redirect = "/"
		}

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

		setAuthSession(w, r, domain, redirect, username)
	default:
		w.WriteHeader(stdhttp.StatusMethodNotAllowed)
	}
}

func setAuthSession(w stdhttp.ResponseWriter, r *stdhttp.Request, domain, redirect, username string) {
	token := uuid.NewString()
	expires := time.Now().Add(24 * time.Hour)
	authSessionsMu.Lock()
	authSessions[token] = authSession{Domain: strings.ToLower(domain), Expires: expires}
	authSessionsMu.Unlock()

	sharedToken := generateSharedToken(username, domain, expires)

	isSecure := r.TLS != nil

	cookie := &stdhttp.Cookie{
		Name:     "sp_auth",
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: stdhttp.SameSiteLaxMode,
	}
	stdhttp.SetCookie(w, cookie)

	sharedCookie := &stdhttp.Cookie{
		Name:     "sp_auth_shared",
		Value:    sharedToken,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: stdhttp.SameSiteLaxMode,
	}
	stdhttp.SetCookie(w, sharedCookie)

	stdhttp.Redirect(w, r, redirect, stdhttp.StatusFound)
}

func handlePasskeyCheck(w stdhttp.ResponseWriter, username string) {
	creds := core.ListPasskeyCredentials(username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"has_passkeys":     len(creds) > 0,
		"registered_today": false,
	})
}

func handlePasskeyRegistration(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	w.Header().Set("Content-Type", "application/json")

	subPath := strings.TrimPrefix(r.URL.Path, "/_auth/passkey/register/")

	if subPath == "start" && r.Method == "POST" {
		var req struct {
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid payload"})
			return
		}

		userID := uuid.NewString()
		challenge := make([]byte, 32)
		rand.Read(challenge)

		host := r.Host
		if i := strings.IndexByte(host, ':'); i > -1 {
			host = host[:i]
		}

		resp := map[string]interface{}{
			"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
			"userId":      base64.RawURLEncoding.EncodeToString([]byte(userID)),
			"username":    req.Username,
			"displayName": req.DisplayName,
			"rp": map[string]string{
				"name": "SparkProxy",
				"id":   host,
			},
			"pubKeyCredParams": []map[string]interface{}{
				{"type": "public-key", "alg": -7},
				{"type": "public-key", "alg": -257},
			},
			"timeout": 60000,
		}

		existingCreds := core.ListPasskeyCredentials(req.Username)
		var credIDs []map[string]string
		for _, cred := range existingCreds {
			credIDs = append(credIDs, map[string]string{
				"id": base64.RawURLEncoding.EncodeToString(cred.CredentialID),
			})
		}
		resp["credentials"] = credIDs

		json.NewEncoder(w).Encode(resp)
		return
	}

	if subPath == "complete" && r.Method == "POST" {
		var req struct {
			Username        string `json:"username"`
			AttestationData string `json:"attestation_data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid payload"})
			return
		}

		attestationData, err := base64.RawURLEncoding.DecodeString(req.AttestationData)
		if err != nil || len(attestationData) < 37 {
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid attestation data"})
			return
		}

		credIDLen := int(attestationData[16])<<8 | int(attestationData[17])
		if len(attestationData) < 37+credIDLen {
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid attestation format"})
			return
		}

		credentialID := attestationData[18 : 18+credIDLen]
		publicKeyData := attestationData[18+credIDLen:]

		_, err = core.CreatePasskeyCredential(req.Username, req.Username, credentialID, publicKeyData, 0, "platform")
		if err != nil {
			w.WriteHeader(stdhttp.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to save credential"})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
		return
	}

	w.WriteHeader(stdhttp.StatusNotFound)
}

func handlePasskeyAuthentication(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	w.Header().Set("Content-Type", "application/json")

	subPath := strings.TrimPrefix(r.URL.Path, "/_auth/passkey/auth/")

	if subPath == "start" && r.Method == "POST" {
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid payload"})
			return
		}

		credentials := core.ListPasskeyCredentials(req.Username)
		if len(credentials) == 0 {
			w.WriteHeader(stdhttp.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "no passkeys found for this user"})
			return
		}

		challenge := make([]byte, 32)
		rand.Read(challenge)

		host := r.Host
		if i := strings.IndexByte(host, ':'); i > -1 {
			host = host[:i]
		}

		var allowCredentials []map[string]interface{}
		for _, cred := range credentials {
			allowCredentials = append(allowCredentials, map[string]interface{}{
				"id":   base64.RawURLEncoding.EncodeToString(cred.CredentialID),
				"type": "public-key",
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"response": map[string]interface{}{
				"challenge":        base64.RawURLEncoding.EncodeToString(challenge),
				"rpId":             host,
				"allowCredentials": allowCredentials,
				"timeout":          60000,
			},
			"session_challenge": base64.RawURLEncoding.EncodeToString(challenge),
			"session_username":  req.Username,
		})
		return
	}

	if subPath == "complete" && r.Method == "POST" {
		var req struct {
			Username          string `json:"username"`
			AuthenticatorData string `json:"authenticator_data"`
			Domain            string `json:"domain"`
			Redirect          string `json:"redirect"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid payload"})
			return
		}

		authData, err := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
		if err != nil || len(authData) < 37 {
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid authenticator data"})
			return
		}

		credentialID := authData[32:68]
		cred := core.GetPasskeyCredentialByID(credentialID)
		if cred == nil {
			w.WriteHeader(stdhttp.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "credential not found"})
			return
		}

		signCount := uint32(authData[33]) | uint32(authData[34])<<8 | uint32(authData[35])<<16 | uint32(authData[36])<<24
		if signCount > cred.SignCount {
			core.UpdatePasskeySignCount(credentialID, signCount)
		}

		domain := strings.TrimSpace(req.Domain)
		redirect := req.Redirect
		if redirect == "" {
			redirect = "/"
		}

		setAuthSession(w, r, domain, redirect, req.Username)
		return
	}

	w.WriteHeader(stdhttp.StatusNotFound)
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
        .card { background:#101018;border:1px solid #1f2937;border-radius:16px;padding:24px;max-width:400px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,0.6); }
        h1 { margin-top:0;font-size:1.4rem;margin-bottom:4px; }
        p { margin-top:0;margin-bottom:20px;color:#9ca3af;font-size:.95rem; }
        label { display:block;font-size:.9rem;margin-bottom:4px;color:#e5e7eb; }
        input { width:100%;padding:10px 12px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;margin-bottom:12px;box-sizing:border-box;font-size:.95rem; }
        input:focus { outline:none;border-color:#fe8032; }
        .btn { width:100%;padding:10px 12px;border-radius:8px;border:1px solid #fe8032;background:#fe8032;color:#022c22;font-weight:600;cursor:pointer;font-size:.95rem;margin-bottom:10px; }
        .btn:hover { background:#f38a48; }
        .btn-secondary { background:transparent;border:1px solid #374151;color:#9ca3af; }
        .btn-secondary:hover { background:#1f2937;border-color:#4b5563; }
        .error { background:#7f1d1d;color:#fecaca;padding:10px 12px;border-radius:8px;font-size:.85rem;margin-bottom:12px; }
        .meta { font-size:.8rem;color:#6b7280;margin-top:12px;text-align:center; }
        .divider { display:flex;align-items:center;margin:16px 0; }
        .divider::before, .divider::after { content:"";flex:1;border-top:1px solid #1f2937; }
        .divider span { padding:0 12px;color:#6b7280;font-size:.85rem; }
        .passkey-section { text-align:center; }
        .passkey-icon { width:64px;height:64px;margin:0 auto 16px;background:rgba(34, 211, 238, 0.1);border-radius:50%;display:flex;align-items:center;justify-content:center; }
        .passkey-icon svg { width:32px;height:32px;color:#22d3ee; }
        .passkey-text { color:#9ca3af;font-size:.9rem;margin-bottom:16px; }
        #password-section.hidden, #passkey-section.hidden, #register-passkey.hidden { display:none; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Authentication required</h1>
        <p>Sign in to access <strong>{{ .Domain }}</strong>.</p>
        {{ if .Error }}<div class="error">{{ .Error }}</div>{{ end }}
        
        <div id="password-section">
            <form method="post" id="password-form" action="/_auth/login?domain={{ .Domain }}&redirect={{ .Redirect }}">
                <input type="hidden" name="domain" id="form-domain" value="{{ .Domain }}">
                <input type="hidden" name="redirect" id="form-redirect" value="{{ .Redirect }}">
                <label for="username">Username or email</label>
                <input id="username" name="username" type="text" autocomplete="username" required />
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required />
                <button class="btn" type="submit">Continue</button>
            </form>
            
            <div class="divider"><span>or</span></div>
            
            <div class="passkey-section">
                <div class="passkey-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>
                </div>
                <p class="passkey-text">Sign in with your fingerprint, face, or security key</p>
                <button class="btn btn-secondary" type="button" id="btn-use-passkey">Use Passkey</button>
            </div>
        </div>

        <div id="passkey-section" class="hidden">
            <div class="passkey-section">
                <div class="passkey-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>
                </div>
                <p class="passkey-text" id="passkey-msg">Authenticate with your passkey</p>
                <button class="btn" type="button" id="btn-auth-passkey">Authenticate</button>
                <button class="btn btn-secondary" type="button" id="btn-back">Back</button>
            </div>
        </div>

        <div id="register-passkey" class="hidden">
            <div class="passkey-section">
                <div class="passkey-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>
                </div>
                <p class="passkey-text">Set up a passkey for easier future sign-ins</p>
                <button class="btn" type="button" id="btn-register-passkey">Register Passkey</button>
                <button class="btn btn-secondary" type="button" id="btn-skip">Skip</button>
            </div>
        </div>

        <div class="meta">Access will be remembered on this device for 24 hours.</div>
    </div>

    <script>
    (function() {
        const passwordSection = document.getElementById('password-section');
        const passkeySection = document.getElementById('passkey-section');
        const registerSection = document.getElementById('register-passkey');
        const btnUsePasskey = document.getElementById('btn-use-passkey');
        const btnAuthPasskey = document.getElementById('btn-auth-passkey');
        const btnBack = document.getElementById('btn-back');
        const btnRegisterPasskey = document.getElementById('btn-register-passkey');
        const btnSkip = document.getElementById('btn-skip');
        const usernameInput = document.getElementById('username');
        const passkeyMsg = document.getElementById('passkey-msg');
        
        let currentUsername = '';
        let sessionData = null;

        btnUsePasskey.addEventListener('click', function() {
            currentUsername = usernameInput.value.trim();
            if (!currentUsername) {
                alert('Please enter your username first');
                usernameInput.focus();
                return;
            }
            passwordSection.classList.add('hidden');
            passkeySection.classList.remove('hidden');
            passkeyMsg.textContent = 'Authenticate with your passkey';
        });

        btnBack.addEventListener('click', function() {
            passkeySection.classList.add('hidden');
            registerSection.classList.add('hidden');
            passwordSection.classList.remove('hidden');
        });

        btnAuthPasskey.addEventListener('click', async function() {
            try {
                const resp = await fetch('/_auth/passkey/auth/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: currentUsername })
                });
                const data = await resp.json();
                if (!resp.ok) {
                    throw new Error(data.error || 'Failed to start passkey authentication');
                }
                
                if (!navigator.credentials || !navigator.credentials.get) {
                    throw new Error('WebAuthn is not supported in this browser');
                }

                const challenge = base64ToArrayBuffer(data.response.challenge);
                const allowCredentials = data.response.allowCredentials.map(cred => ({
                    id: base64ToArrayBuffer(cred.id),
                    type: 'public-key',
                    transports: ['internal', 'hybrid']
                }));

                const publicKey = {
                    challenge: challenge,
                    rpId: data.response.rpId,
                    allowCredentials: allowCredentials,
                    timeout: data.response.timeout || 60000
                };

                const assertion = await navigator.credentials.get({ publicKey });
                
                const authData = assertion.response.authenticatorData;
                const signature = assertion.response.signature;

                const completeResp = await fetch('/_auth/passkey/auth/complete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: currentUsername,
                        authenticator_data: arrayBufferToBase64URL(authData),
                        signature: arrayBufferToBase64URL(signature),
                        challenge: data.session_challenge,
                        domain: new URLSearchParams(window.location.search).get('domain') || '',
                        redirect: new URLSearchParams(window.location.search).get('redirect') || '/'
                    })
                });
                const completeData = await completeResp.json();
                
                if (!completeResp.ok) {
                    throw new Error(completeData.error || 'Passkey authentication failed');
                }

                window.location.href = '{{ .Redirect }}';
            } catch (err) {
                alert('Passkey authentication failed: ' + err.message);
                console.error(err);
            }
        });

        btnRegisterPasskey.addEventListener('click', async function() {
            try {
                const resp = await fetch('/_auth/passkey/register/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: currentUsername, display_name: currentUsername })
                });
                const data = await resp.json();
                if (!resp.ok) {
                    throw new Error(data.error || 'Failed to start passkey registration');
                }

                if (!navigator.credentials || !navigator.credentials.create) {
                    throw new Error('WebAuthn is not supported in this browser');
                }

                const userID = base64ToArrayBuffer(data.response.userId);
                const challenge = base64ToArrayBuffer(data.response.challenge);
                
                const excludeCredentials = (data.response.credentials || []).map(cred => ({
                    id: base64ToArrayBuffer(cred.id),
                    type: 'public-key',
                    transports: ['internal', 'hybrid']
                }));

                const publicKey = {
                    challenge: challenge,
                    rp: {
                        name: data.response.rp.name,
                        id: data.response.rp.id
                    },
                    user: {
                        id: userID,
                        name: data.response.username,
                        displayName: data.response.displayName || data.response.username
                    },
                    pubKeyCredParams: data.response.pubKeyCredParams.map(p => ({
                        type: p.type,
                        alg: p.alg
                    })),
                    excludeCredentials: excludeCredentials,
                    timeout: data.response.timeout || 60000
                };

                const credential = await navigator.credentials.create({ publicKey });
                
                const completeResp = await fetch('/_auth/passkey/register/complete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: currentUsername,
                        attestation_data: arrayBufferToBase64URL(credential.response),
                        challenge: data.session_challenge
                    })
                });
                const completeData = await completeResp.json();
                
                if (!completeResp.ok) {
                    throw new Error(completeData.error || 'Failed to complete passkey registration');
                }

                alert('Passkey registered successfully!');
                passkeySection.classList.add('hidden');
                registerSection.classList.add('hidden');
                passwordSection.classList.remove('hidden');
            } catch (err) {
                alert('Passkey registration failed: ' + err.message);
                console.error(err);
            }
        });

        btnSkip.addEventListener('click', function() {
            registerSection.classList.add('hidden');
            passwordSection.classList.remove('hidden');
        });

        document.getElementById('password-form').addEventListener('submit', function(e) {
            currentUsername = usernameInput.value.trim();
            localStorage.setItem('last_username', currentUsername);
            
            const urlParams = new URLSearchParams(window.location.search);
            document.getElementById('form-domain').value = urlParams.get('domain') || '';
            document.getElementById('form-redirect').value = urlParams.get('redirect') || '/';
        });

        if (localStorage.getItem('last_username')) {
            usernameInput.value = localStorage.getItem('last_username');
        }

        function base64ToArrayBuffer(base64) {
            let base64Standard = base64
                .replace(/-/g, '+')
                .replace(/_/g, '/');
            while (base64Standard.length % 4 !== 0) {
                base64Standard += '=';
            }
            const binary = atob(base64Standard);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }

        function arrayBufferToBase64URL(buffer) {
            const base64 = arrayBufferToBase64(buffer);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }
    })();

    </script>
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
