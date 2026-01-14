package http

import (
	"crypto/tls"
	"fmt"
	"net"
	stdhttp "net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	filepkg "frostlink-go/file"
	logger "frostlink-go/logger"
)

func StartProxy(configs []filepkg.Config) error {
	addr := os.Getenv("PROXY_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		host := r.Host
		cfg, ok := findConfigByHost(configs, host)
		if !ok {
			w.WriteHeader(stdhttp.StatusNotFound)
			_, _ = w.Write([]byte("<html><body><h1>404 Not Found</h1></body></html>"))
			return
		}
		if !cfg.AllowHTTP {
			w.WriteHeader(stdhttp.StatusForbidden)
			_, _ = w.Write([]byte("HTTP disabled for this domain"))
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

		proxy.ServeHTTP(w, r)
	})

	logger.SystemLog("info", "http-proxy", fmt.Sprintf("Listening on %s", addr))
	go startTLSProxyIfAvailable(configs, mux)
	return stdhttp.ListenAndServe(addr, mux)
}

func findConfigByHost(configs []filepkg.Config, host string) (filepkg.Config, bool) {
	name := host
	if i := strings.IndexByte(name, ':'); i > -1 {
		name = name[:i]
	}
	for _, c := range configs {
		if strings.EqualFold(c.Domain, name) {
			return c, true
		}
	}
	return filepkg.Config{}, false
}

func startTLSProxyIfAvailable(configs []filepkg.Config, handler stdhttp.Handler) {
	certMap := make(map[string]*tls.Certificate)
	for _, c := range configs {
		if !c.AllowSSL {
			continue
		}
		if c.SSLCertificate == nil || c.SSLCertificateKey == nil {
			continue
		}
		pub := strings.TrimSpace(*c.SSLCertificate)
		priv := strings.TrimSpace(*c.SSLCertificateKey)
		if pub == "" || priv == "" {
			continue
		}
		cert, err := tls.LoadX509KeyPair(pub, priv)
		if err != nil {
			logger.SystemLog("error", "tls-cert", fmt.Sprintf("Failed to load cert for %s: %v", c.Domain, err))
			continue
		}
		certMap[c.Domain] = &cert
	}

	if len(certMap) == 0 {
		return
	}

	tlsAddr := os.Getenv("PROXY_TLS_ADDR")
	if tlsAddr == "" {
		tlsAddr = ":8443"
	}

	getCert := func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if chi == nil {
			return nil, fmt.Errorf("no client hello info")
		}
		name := chi.ServerName
		if cert, ok := certMap[name]; ok {
			return cert, nil
		}
		return nil, fmt.Errorf("no certificate for %s", name)
	}

	tlsCfg := &tls.Config{GetCertificate: getCert}
	ln, err := net.Listen("tcp", tlsAddr)
	if err != nil {
		logger.SystemLog("error", "tls-listen", fmt.Sprintf("TLS listen error on %s: %v", tlsAddr, err))
		return
	}
	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &stdhttp.Server{Handler: handler}

	go func() {
		logger.SystemLog("info", "https-proxy", fmt.Sprintf("Listening on %s", tlsAddr))
		if err := srv.Serve(tlsLn); err != nil && err != stdhttp.ErrServerClosed {
			logger.SystemLog("error", "https-proxy", fmt.Sprintf("Server error: %v", err))
		}
	}()
}
