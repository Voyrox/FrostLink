package file

import (
	"io/ioutil"
	"path/filepath"
	"strings"
)

// Config mirrors the configuration file structure
type Config struct {
	Domain            string  `json:"domain"`
	Location          string  `json:"host"`
	AllowSSL          bool    `json:"SSL"`
	AllowHTTP         bool    `json:"HTTP"`
	SSLCertificate    *string `json:"pubkey"`
	SSLCertificateKey *string `json:"privkey"`
}

// ReadConfigs reads all .conf files in dir and returns parsed configs
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

// ParseConfig parses a single config file content
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
	// If SSL requested, ensure certs present
	if ssl && (pubStr == nil || privStr == nil) {
		return "", "", false, true, nil, nil, false
	}
	return d, l, ssl, httpOk, pubStr, privStr, true
}
