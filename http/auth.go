package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	filepkg "SparkProxy/file"
	logger "SparkProxy/logger"

	"github.com/google/uuid"
)

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
	if err := os.MkdirAll(filepath.Dir(authCfgPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(authCfgPath, data, 0o600)
}

func isAuthorizedForDomain(domain string, r *http.Request) bool {
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

func redirectToAuthLogin(w http.ResponseWriter, r *http.Request, cfg filepkg.Config) {
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
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
}

func handleAuthRoutes(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/_auth/login" {
		http.NotFound(w, r)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}

	switch r.Method {
	case http.MethodGet:
		renderAuthLoginPage(w, domain, redirect, "")
	case http.MethodPost:
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
			logger.SystemLog("error", "domain-auth", fmt.Sprintf("auth API error for domain %s: %v", domain, err))
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

		cookie := &http.Cookie{
			Name:     "sp_auth",
			Value:    token,
			Path:     "/",
			Expires:  expires,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)

		http.Redirect(w, r, redirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
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

	resp, err := http.Post(authURL.String(), "application/json", bytes.NewReader(data))
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
        .btn { width:100%;padding:9px 10px;border-radius:8px;border:1px solid #22c55e;background:#22c55e;color:#022c22;font-weight:600;cursor:pointer; }
        .btn:hover { background:#16a34a; }
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

func renderAuthLoginPage(w http.ResponseWriter, domain, redirect, errMsg string) {
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
		logger.SystemLog("error", "domain-auth", fmt.Sprintf("failed to render auth login page: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Authentication page error"))
	}
}
