package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"SparkProxy/core"
)

const certsPath = "db/certs"

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
	metaPath := filepath.Join(certsPath, "live", domain, "cert.json")
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
	certPath := filepath.Join(certsPath, "live", domain, "cert.pem")
	keyPath := filepath.Join(certsPath, "live", domain, "privkey.pem")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func GetCertificateInfo(domain string) (*CertificateInfo, error) {
	certPath := filepath.Join(certsPath, "live", domain, "cert.pem")
	keyPath := filepath.Join(certsPath, "live", domain, "privkey.pem")

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
		IssuerPath: filepath.Join(certsPath, "live", domain, "issuer.pem"),
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
		Domain:      domain,
		CertPath:    certPath,
		KeyPath:     keyPath,
		IssuerPath:  "",
		ExpiresAt:   expiresAt,
		DaysLeft:    int(time.Until(expiresAt).Hours() / 24),
		AutoManaged: false,
	}, nil
}

func ListCertificates() []CertificateInfo {
	livePath := filepath.Join(certsPath, "live")
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
	domainPath := filepath.Join(certsPath, "live", domain)
	return os.RemoveAll(domainPath)
}

func CertificateExists(domain string) bool {
	certPath := filepath.Join(certsPath, "live", domain, "cert.pem")
	_, err := os.Stat(certPath)
	return err == nil
}

func GetCertificatePath(domain string) string {
	return filepath.Join(certsPath, "live", domain, "cert.pem")
}

func GetKeyPath(domain string) string {
	return filepath.Join(certsPath, "live", domain, "privkey.pem")
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
