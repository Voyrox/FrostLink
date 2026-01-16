package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	stdhttp "net/http"
	"os"
	"strings"
	"sync"

	"SparkProxy/core"
	"SparkProxy/ui"
)

var (
	certMu      sync.RWMutex
	staticCerts = make(map[string]*tls.Certificate)
	acmeCerts   = make(map[string]*tls.Certificate)
)

func loadCertAndKey(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(certPath), strings.TrimSpace(keyPath))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func LoadStaticCerts(configs []core.Config) {
	certMu.Lock()
	defer certMu.Unlock()

	for _, c := range configs {
		if !c.AllowSSL || c.SSLCertificate == nil || c.SSLCertificateKey == nil {
			continue
		}
		pub := strings.TrimSpace(*c.SSLCertificate)
		priv := strings.TrimSpace(*c.SSLCertificateKey)
		if pub == "" || priv == "" {
			continue
		}
		cert, err := loadCertAndKey(pub, priv)
		if err != nil {
			ui.SystemLog("error", "tls-cert", fmt.Sprintf("Failed to load cert for %s: %v", c.Domain, err))
			continue
		}
		staticCerts[c.Domain] = cert
	}
}

func GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if chi == nil {
		return nil, fmt.Errorf("no client hello info")
	}
	name := chi.ServerName
	if name == "" {
		return nil, fmt.Errorf("no SNI provided")
	}

	certMu.RLock()
	if cert, ok := acmeCerts[name]; ok {
		certMu.RUnlock()
		return cert, nil
	}
	certMu.RUnlock()

	certMu.RLock()
	if cert, ok := staticCerts[name]; ok {
		certMu.RUnlock()
		return cert, nil
	}
	certMu.RUnlock()

	if cert, err := LoadCertificate(name); err == nil {
		certMu.Lock()
		acmeCerts[name] = cert
		certMu.Unlock()
		return cert, nil
	}

	certMu.RLock()
	cfg, ok := core.GetDomainConfig(name)
	certMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no certificate for %s", name)
	}

	if cfg.SSLCertificate != nil && cfg.SSLCertificateKey != nil &&
		*cfg.SSLCertificate != "" && *cfg.SSLCertificateKey != "" {
		if ValidateCertificatePaths(*cfg.SSLCertificate, *cfg.SSLCertificateKey) == nil {
			cert, err := loadCertAndKey(*cfg.SSLCertificate, *cfg.SSLCertificateKey)
			if err == nil {
				certMu.Lock()
				staticCerts[name] = cert
				certMu.Unlock()
				return cert, nil
			}
		}

		if certPath, keyPath, found, err := AutoDetectAndAdopt(name); err == nil && found {
			cert, err := loadCertAndKey(certPath, keyPath)
			if err == nil {
				certMu.Lock()
				staticCerts[name] = cert
				certMu.Unlock()
				return cert, nil
			}
		}
	}

	return nil, fmt.Errorf("no certificate for %s", name)
}

func ReloadCertificate(domain string) error {
	certMu.Lock()
	defer certMu.Unlock()

	delete(acmeCerts, domain)

	cert, err := LoadCertificate(domain)
	if err != nil {
		return err
	}
	acmeCerts[domain] = cert
	return nil
}

func StartTLSProxy(configs []core.Config, handler stdhttp.Handler) {
	LoadStaticCerts(configs)

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
		cert, err := loadCertAndKey(pub, priv)
		if err != nil {
			ui.SystemLog("error", "tls-cert", fmt.Sprintf("Failed to load cert for %s: %v", c.Domain, err))
			continue
		}
		certMap[c.Domain] = cert
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
		return GetCertificate(chi)
	}

	tlsCfg := &tls.Config{GetCertificate: getCert}
	ln, err := net.Listen("tcp", tlsAddr)
	if err != nil {
		ui.SystemLog("error", "tls-listen", fmt.Sprintf("TLS listen error on %s: %v", tlsAddr, err))
		return
	}
	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &stdhttp.Server{Handler: handler}

	go func() {
		ui.SystemLog("info", "https-proxy", fmt.Sprintf("Listening on %s", tlsAddr))
		if err := srv.Serve(tlsLn); err != nil && err != stdhttp.ErrServerClosed {
			ui.SystemLog("error", "https-proxy", fmt.Sprintf("Server error: %v", err))
		}
	}()
}
