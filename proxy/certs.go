package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const certsPath = "db/certs"

type CertificateInfo struct {
	Domain      string    `json:"domain"`
	CertPath    string    `json:"cert_path"`
	KeyPath     string    `json:"key_path"`
	IssuerPath  string    `json:"issuer_path"`
	ExpiresAt   time.Time `json:"expires_at"`
	DaysLeft    int       `json:"days_left"`
	AutoManaged bool      `json:"auto_managed"`
}

type certMeta struct {
	Domain      string    `json:"domain"`
	ExpiresAt   time.Time `json:"expires_at"`
	AutoManaged bool      `json:"auto_managed"`
	Provider    string    `json:"provider,omitempty"`
	UseStaging  bool      `json:"use_staging,omitempty"`
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

	metaPath := filepath.Join(certsPath, "live", domain, "cert.json")
	autoManaged := false
	if metaData, err := os.ReadFile(metaPath); err == nil {
		var meta certMeta
		if json.Unmarshal(metaData, &meta) == nil {
			autoManaged = meta.AutoManaged
		}
	}

	return &CertificateInfo{
		Domain:      domain,
		CertPath:    certPath,
		KeyPath:     keyPath,
		IssuerPath:  filepath.Join(certsPath, "live", domain, "issuer.pem"),
		ExpiresAt:   expiresAt,
		DaysLeft:    int(time.Until(expiresAt).Hours() / 24),
		AutoManaged: autoManaged,
	}, nil
}

func ListCertificates() []CertificateInfo {
	livePath := filepath.Join(certsPath, "live")
	entries, _ := os.ReadDir(livePath)

	var certs []CertificateInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if info, err := GetCertificateInfo(entry.Name()); err == nil {
			certs = append(certs, *info)
		}
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
