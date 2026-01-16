package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"SparkProxy/core"
	"SparkProxy/ui"
)

type CertificateSource string

const (
	SourceCustom CertificateSource = "custom"
	SourceAuto   CertificateSource = "auto"
	SourceNone   CertificateSource = "none"
)

type CertificateInfo struct {
	Domain     string            `json:"domain"`
	Source     CertificateSource `json:"source"`
	CertPath   string            `json:"cert_path,omitempty"`
	KeyPath    string            `json:"key_path,omitempty"`
	IssuerPath string            `json:"issuer_path,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty"`
	DaysLeft   int               `json:"days_left,omitempty"`
	Provider   string            `json:"provider,omitempty"`
	UseStaging bool              `json:"use_staging,omitempty"`
}

type certMeta struct {
	Source     CertificateSource `json:"source"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Provider   string            `json:"provider,omitempty"`
	UseStaging bool              `json:"use_staging,omitempty"`
}

func getCertMeta(domain string) certMeta {
	metaPath := filepath.Join(getCertsPath(), "live", domain, "cert.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return certMeta{Source: SourceNone}
	}
	var meta certMeta
	if json.Unmarshal(data, &meta) == nil {
		return meta
	}
	return certMeta{Source: SourceNone}
}

func LoadCertificate(domain string) (*tls.Certificate, error) {
	certPath := filepath.Join(getCertsPath(), "live", domain, "cert.pem")
	keyPath := filepath.Join(getCertsPath(), "live", domain, "privkey.pem")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func GetCertificateInfo(domain string) (*CertificateInfo, error) {
	certPath := filepath.Join(getCertsPath(), "live", domain, "cert.pem")
	keyPath := filepath.Join(getCertsPath(), "live", domain, "privkey.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	var expiresAt time.Time
	if len(cert.Certificate) > 0 {
		if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			expiresAt = parsed.NotAfter
		}
	}

	meta := getCertMeta(domain)

	return &CertificateInfo{
		Domain:     domain,
		Source:     meta.Source,
		CertPath:   certPath,
		KeyPath:    keyPath,
		IssuerPath: filepath.Join(getCertsPath(), "live", domain, "issuer.pem"),
		ExpiresAt:  expiresAt,
		DaysLeft:   int(time.Until(expiresAt).Hours() / 24),
		Provider:   meta.Provider,
		UseStaging: meta.UseStaging,
	}, nil
}

func GetCertificateInfoForDomain(domain string, customCertPath, customKeyPath *string) *CertificateInfo {
	if customCertPath != nil && *customCertPath != "" && customKeyPath != nil && *customKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(*customCertPath, *customKeyPath)
		if err == nil {
			var expiresAt time.Time
			if len(cert.Certificate) > 0 {
				if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
					expiresAt = parsed.NotAfter
				}
			}
			return &CertificateInfo{
				Domain:    domain,
				Source:    SourceCustom,
				CertPath:  *customCertPath,
				KeyPath:   *customKeyPath,
				ExpiresAt: expiresAt,
				DaysLeft:  int(time.Until(expiresAt).Hours() / 24),
			}
		}
	}

	autoCert, err := GetCertificateInfo(domain)
	if err == nil {
		return autoCert
	}

	return &CertificateInfo{
		Domain: domain,
		Source: SourceNone,
	}
}

func GetCustomCertificateInfo(domain, certPath, keyPath string) (*CertificateInfo, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	var expiresAt time.Time
	if len(cert.Certificate) > 0 {
		if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			expiresAt = parsed.NotAfter
		}
	}

	return &CertificateInfo{
		Domain:     domain,
		CertPath:   certPath,
		KeyPath:    keyPath,
		IssuerPath: "",
		ExpiresAt:  expiresAt,
		DaysLeft:   int(time.Until(expiresAt).Hours() / 24),
	}, nil
}

func ListCertificates() []CertificateInfo {
	livePath := filepath.Join(getCertsPath(), "live")
	entries, _ := os.ReadDir(livePath)

	certMap := make(map[string]CertificateInfo)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if info, err := GetCertificateInfo(entry.Name()); err == nil {
			certMap[info.Domain] = *info
		}
	}

	domainCfgs := core.ReadConfigs("./domains")
	for _, cfg := range domainCfgs {
		if cfg.SSLCertificate != nil && cfg.SSLCertificateKey != nil {
			certPath := *cfg.SSLCertificate
			keyPath := *cfg.SSLCertificateKey
			if certPath != "" && keyPath != "" {
				if info, err := GetCustomCertificateInfo(cfg.Domain, certPath, keyPath); err == nil {
					if _, exists := certMap[info.Domain]; !exists {
						certMap[info.Domain] = *info
					}
				}
			}
		}
	}

	var certs []CertificateInfo
	for _, cert := range certMap {
		certs = append(certs, cert)
	}
	return certs
}

func RevokeCertificate(domain string) error {
	domainPath := filepath.Join(getCertsPath(), "live", domain)
	return os.RemoveAll(domainPath)
}

func CertificateExists(domain string) bool {
	certPath := filepath.Join(getCertsPath(), "live", domain, "cert.pem")
	_, err := os.Stat(certPath)
	return err == nil
}

func GetCertificatePath(domain string) string {
	return filepath.Join(getCertsPath(), "live", domain, "cert.pem")
}

func GetKeyPath(domain string) string {
	return filepath.Join(getCertsPath(), "live", domain, "privkey.pem")
}

func DaysUntilExpiry(domain string) (int, error) {
	info, err := GetCertificateInfo(domain)
	if err != nil {
		return 0, err
	}
	return info.DaysLeft, nil
}

func IsExpiringSoon(domain string, days int) (bool, error) {
	daysLeft, err := DaysUntilExpiry(domain)
	if err != nil {
		return false, err
	}
	return daysLeft <= days, nil
}

var defaultCertSearchPaths = []string{
	"/etc/letsencrypt/live",
	"/var/lib/letsencrypt/live",
	"/etc/ssl/letsencrypt/live",
}

func AutoDetectCertificate(domain string) (certPath, keyPath string, found bool) {
	for _, basePath := range defaultCertSearchPaths {
		candidates := []struct {
			cert string
			key  string
		}{
			{filepath.Join(basePath, domain, "fullchain.pem"), filepath.Join(basePath, domain, "privkey.pem")},
			{filepath.Join(basePath, domain, "cert.pem"), filepath.Join(basePath, domain, "privkey.pem")},
		}

		for _, c := range candidates {
			if ValidateCertificatePaths(c.cert, c.key) == nil {
				return c.cert, c.key, true
			}
		}
	}
	return "", "", false
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

func AutoDetectAndAdopt(domain string) (certPath, keyPath string, found bool, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", "", false, fmt.Errorf("domain is required")
	}

	certPath, keyPath, found = AutoDetectCertificate(domain)
	if !found {
		return "", "", false, nil
	}

	if err := core.UpdateDomainCertPaths(domain, certPath, keyPath); err != nil {
		ui.SystemLog("error", "ssl", fmt.Sprintf("Failed to auto-adopt cert for %s: %v", domain, err))
		return "", "", false, fmt.Errorf("failed to save certificate paths: %w", err)
	}

	ui.SystemLog("info", "ssl", fmt.Sprintf("Auto-detected and adopted certificate for %s from %s", domain, certPath))
	return certPath, keyPath, true, nil
}

func GetEffectiveCertificateInfo(domain string) (*CertificateInfo, error) {
	cfg, ok := core.GetDomainConfig(domain)
	if !ok {
		return nil, fmt.Errorf("domain not found: %s", domain)
	}

	if cfg.SSLCertificate != nil && cfg.SSLCertificateKey != nil &&
		*cfg.SSLCertificate != "" && *cfg.SSLCertificateKey != "" {
		info, err := GetCustomCertificateInfo(domain, *cfg.SSLCertificate, *cfg.SSLCertificateKey)
		if err == nil {
			return info, nil
		}

		if certPath, keyPath, found, err := AutoDetectAndAdopt(domain); err == nil {
			if found {
				ui.SystemLog("info", "ssl",
					fmt.Sprintf("Auto-detected and adopted certificate for %s from %s", domain, certPath))
				return GetCustomCertificateInfo(domain, certPath, keyPath)
			}
		} else {
			ui.SystemLog("warn", "ssl",
				fmt.Sprintf("Failed to auto-detect certificate for %s: %v", domain, err))
		}
	}

	if CertificateExists(domain) {
		return GetCertificateInfo(domain)
	}

	return &CertificateInfo{
		Domain: domain,
		Source: SourceNone,
	}, nil
}
