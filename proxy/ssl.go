package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	stdhttp "net/http"
	"os"
	"strings"

	"SparkProxy/core"
	"SparkProxy/ui"
)

func loadCertAndKey(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(certPath), strings.TrimSpace(keyPath))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func StartTLSProxy(configs []core.Config, handler stdhttp.Handler) {
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
