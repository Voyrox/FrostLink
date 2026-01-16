package core

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Domain            string  `json:"domain"`
	Location          string  `json:"host"`
	AllowSSL          bool    `json:"SSL"`
	AllowHTTP         bool    `json:"HTTP"`
	SSLCertificate    *string `json:"pubkey"`
	SSLCertificateKey *string `json:"privkey"`
}

func ReadConfigs(dir string) []Config {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return []Config{}
	}
	var cfgs []Config
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".conf" {
			continue
		}
		b, err := ioutil.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		domain, location, ssl, httpOk, pub, priv, ok := ParseConfig(string(b))
		if !ok {
			continue
		}
		cfgs = append(cfgs, Config{Domain: domain, Location: location, AllowSSL: ssl, AllowHTTP: httpOk, SSLCertificate: pub, SSLCertificateKey: priv})
	}
	return cfgs
}

func ParseConfig(content string) (domain, location string, allowSSL, allowHTTP bool, pub, priv *string, ok bool) {
	lines := strings.Split(content, "\n")
	var d, l string
	var sslPtr, httpPtr *bool
	var pubStr, privStr *string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "domain: ") {
			d = strings.TrimPrefix(line, "domain: ")
		} else if strings.HasPrefix(line, "location: ") {
			l = strings.TrimPrefix(line, "location: ")
		} else if strings.HasPrefix(line, "AllowSSL: ") {
			v := strings.TrimPrefix(line, "AllowSSL: ")
			b := v == "true" || v == "1"
			sslPtr = &b
		} else if strings.HasPrefix(line, "AllowHTTP: ") {
			v := strings.TrimPrefix(line, "AllowHTTP: ")
			b := v == "true" || v == "1"
			httpPtr = &b
		} else if strings.HasPrefix(line, "ssl_certificate: ") {
			s := strings.TrimPrefix(line, "ssl_certificate: ")
			pubStr = &s
		} else if strings.HasPrefix(line, "ssl_certificate_key: ") {
			s := strings.TrimPrefix(line, "ssl_certificate_key: ")
			privStr = &s
		}
	}
	if d == "" || l == "" {
		return "", "", false, true, nil, nil, false
	}
	ssl := false
	if sslPtr != nil {
		ssl = *sslPtr
	}
	httpOk := true
	if httpPtr != nil {
		httpOk = *httpPtr
	}
	if ssl && (pubStr == nil || privStr == nil) {
		return "", "", false, true, nil, nil, false
	}
	return d, l, ssl, httpOk, pubStr, privStr, true
}

func WriteConfig(dir string, cfg Config) error {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	fileName := strings.TrimSpace(cfg.Domain)
	if fileName == "" {
		fileName = "domain"
	}
	path := filepath.Join(dir, fileName+".conf")

	var b strings.Builder
	b.WriteString("server: {\n")
	b.WriteString("    domain: " + cfg.Domain + "\n")
	b.WriteString("    location: " + cfg.Location + "\n\n")
	b.WriteString("    connection: {\n")
	if cfg.AllowSSL {
		b.WriteString("        AllowSSL: true\n")
	} else {
		b.WriteString("        AllowSSL: false\n")
	}
	if cfg.AllowHTTP {
		b.WriteString("        AllowHTTP: true\n")
	} else {
		b.WriteString("        AllowHTTP: false\n")
	}
	b.WriteString("    }\n")
	b.WriteString("}\n\n")

	pub := ""
	if cfg.SSLCertificate != nil {
		pub = strings.TrimSpace(*cfg.SSLCertificate)
	}
	priv := ""
	if cfg.SSLCertificateKey != nil {
		priv = strings.TrimSpace(*cfg.SSLCertificateKey)
	}
	if pub != "" || priv != "" {
		b.WriteString("SSLCert: {\n")
		if pub != "" {
			b.WriteString("    ssl_certificate: " + pub + "\n")
		}
		if priv != "" {
			b.WriteString("    ssl_certificate_key: " + priv + "\n")
		}
		b.WriteString("}\n")
	}

	return ioutil.WriteFile(path, []byte(b.String()), 0644)
}

func GetDomainConfig(domain string) (Config, bool) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return Config{}, false
	}
	path := filepath.Join(".", "domains", domain+".conf")
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, false
	}
	d, l, ssl, httpOk, pub, priv, ok := ParseConfig(string(b))
	if !ok {
		return Config{}, false
	}
	return Config{Domain: d, Location: l, AllowSSL: ssl, AllowHTTP: httpOk, SSLCertificate: pub, SSLCertificateKey: priv}, true
}

func UpdateDomain(domain string, target string, allowSSL, allowHTTP bool, certFile, keyFile string) error {
	cfg, ok := GetDomainConfig(domain)
	if !ok {
		return os.ErrNotExist
	}

	cfg.Location = strings.TrimSpace(target)
	cfg.AllowSSL = allowSSL
	cfg.AllowHTTP = allowHTTP

	if certFile != "" {
		s := strings.TrimSpace(certFile)
		cfg.SSLCertificate = &s
	}
	if keyFile != "" {
		s := strings.TrimSpace(keyFile)
		cfg.SSLCertificateKey = &s
	}

	return WriteConfig(".", cfg)
}

func ValidateCertificatePaths(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("certificate or key path is empty")
	}

	certStat, err := os.Stat(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("certificate file does not exist: %s", certPath)
		}
		return fmt.Errorf("cannot access certificate file: %w", err)
	}
	if certStat.IsDir() {
		return fmt.Errorf("certificate path is a directory: %s", certPath)
	}

	keyStat, err := os.Stat(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key file does not exist: %s", keyPath)
		}
		return fmt.Errorf("cannot access key file: %w", err)
	}
	if keyStat.IsDir() {
		return fmt.Errorf("key path is a directory: %s", keyPath)
	}

	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate pair: %w", err)
	}

	return nil
}

func UpdateDomainCertPaths(domain string, certFile, keyFile string) error {
	cfg, ok := GetDomainConfig(domain)
	if !ok {
		return os.ErrNotExist
	}

	if certFile != "" && keyFile != "" {
		certTrimmed := strings.TrimSpace(certFile)
		keyTrimmed := strings.TrimSpace(keyFile)
		cfg.SSLCertificate = &certTrimmed
		cfg.SSLCertificateKey = &keyTrimmed
	} else {
		if certFile != "" {
			s := strings.TrimSpace(certFile)
			cfg.SSLCertificate = &s
		}
		if keyFile != "" {
			s := strings.TrimSpace(keyFile)
			cfg.SSLCertificateKey = &s
		}
	}

	if err := WriteConfig(".", cfg); err != nil {
		return err
	}

	return nil
}

func DeleteDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return os.ErrInvalid
	}
	path := filepath.Join(".", "domains", domain+".conf")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.ErrNotExist
	}
	return os.Remove(path)
}
