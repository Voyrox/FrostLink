package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

func getCertsPath() string {
	if p := os.Getenv("SP_CERTS_PATH"); p != "" {
		return p
	}
	return "/etc/letsencrypt"
}

const (
	acmeProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type ACMEClient struct {
	client     *lego.Client
	email      string
	accountKey crypto.PrivateKey
	dataPath   string
	useStaging bool
}

type ACMECertificate struct {
	Domain     string
	CertPath   string
	KeyPath    string
	IssuerPath string
	ExpiresAt  time.Time
	Serial     string
}

type acmeUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func NewACMEClient(email string, dataPath string, useStaging bool) (*ACMEClient, error) {
	if email == "" {
		return nil, fmt.Errorf("email is required for ACME account")
	}

	key, err := loadOrCreateAccountKey(dataPath, email)
	if err != nil {
		return nil, fmt.Errorf("failed to load/create account key: %w", err)
	}

	user := &acmeUser{
		email: email,
		key:   key,
	}

	config := lego.NewConfig(user)
	if useStaging {
		config.CADirURL = acmeStagingURL
	} else {
		config.CADirURL = acmeProdURL
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		if reg != nil {
			user.registration = reg
		}
	} else {
		user.registration = reg
	}

	saveAccountRegistration(dataPath, email, user.registration)

	return &ACMEClient{
		client:     client,
		email:      email,
		accountKey: key,
		dataPath:   dataPath,
		useStaging: useStaging,
	}, nil
}

func (c *ACMEClient) SetCloudflareProvider(apiToken string, apiEmail string, apiKey string, zoneToken string) error {
	config := cloudflare.NewDefaultConfig()

	if apiEmail != "" && apiKey != "" {
		config.AuthEmail = apiEmail
		config.AuthKey = apiKey
	} else if apiToken != "" {
		config.AuthToken = apiToken
	} else {
		return fmt.Errorf("cloudflare credentials required: either API token or API key+email")
	}

	if zoneToken != "" {
		config.ZoneToken = zoneToken
	}

	provider, err := cloudflare.NewDNSProviderConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create cloudflare provider: %w", err)
	}

	err = c.client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return fmt.Errorf("failed to set DNS provider: %w", err)
	}
	return nil
}

func parseCertFromPEMOrDER(data []byte) (*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no certificate data")
	}

	if data[0] == '-' {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		return x509.ParseCertificate(block.Bytes)
	}

	return x509.ParseCertificate(data)
}

func (c *ACMEClient) ObtainCertificate(domain string) (*ACMECertificate, error) {
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certs, err := c.client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	certPath, err := saveCertificate(c.dataPath, domain, certs)
	if err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	x509Cert, err := parseCertFromPEMOrDER(certs.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &ACMECertificate{
		Domain:     domain,
		CertPath:   certPath,
		KeyPath:    filepath.Join(filepath.Dir(certPath), "privkey.pem"),
		IssuerPath: filepath.Join(filepath.Dir(certPath), "issuer.pem"),
		ExpiresAt:  x509Cert.NotAfter,
		Serial:     fmt.Sprintf("%x", x509Cert.SerialNumber),
	}, nil
}

func (c *ACMEClient) RenewCertificate(domain string) (*ACMECertificate, error) {
	certsPath := getCertsPath()
	certPath := filepath.Join(certsPath, "live", domain, "cert.pem")
	keyPath := filepath.Join(certsPath, "live", domain, "privkey.pem")
	issuerPath := filepath.Join(certsPath, "live", domain, "issuer.pem")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	issuerPEM, _ := os.ReadFile(issuerPath)

	certs, err := c.client.Certificate.Renew(certificate.Resource{
		Domain:            domain,
		CertURL:           "",
		CertStableURL:     "",
		PrivateKey:        keyPEM,
		Certificate:       certPEM,
		IssuerCertificate: issuerPEM,
		CSR:               nil,
	}, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	certPath, err = saveCertificate(c.dataPath, domain, certs)
	if err != nil {
		return nil, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	x509Cert, err := parseCertFromPEMOrDER(certs.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	return &ACMECertificate{
		Domain:     domain,
		CertPath:   certPath,
		KeyPath:    filepath.Join(filepath.Dir(certPath), "privkey.pem"),
		IssuerPath: filepath.Join(filepath.Dir(certPath), "issuer.pem"),
		ExpiresAt:  x509Cert.NotAfter,
		Serial:     fmt.Sprintf("%x", x509Cert.SerialNumber),
	}, nil
}

func loadOrCreateAccountKey(dataPath string, email string) (crypto.PrivateKey, error) {
	accountDir := filepath.Join(getCertsPath(), "accounts", sanitizeEmail(email))
	keyPath := filepath.Join(accountDir, "account.key")

	if _, err := os.Stat(keyPath); err == nil {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		key, err := certcrypto.ParsePEMPrivateKey(data)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	os.MkdirAll(accountDir, 0700)
	pemData := certcrypto.PEMEncode(privateKey)
	os.WriteFile(keyPath, pemData, 0600)

	return privateKey, nil
}

func saveAccountRegistration(dataPath string, email string, reg *registration.Resource) {
	accountDir := filepath.Join(getCertsPath(), "accounts", sanitizeEmail(email))
	os.MkdirAll(accountDir, 0700)

	regData := map[string]interface{}{
		"uri": reg.URI,
	}
	data, _ := json.MarshalIndent(regData, "", "  ")
	os.WriteFile(filepath.Join(accountDir, "registration.json"), data, 0600)
}

func saveCertificate(dataPath, domain string, certs *certificate.Resource) (string, error) {
	certsPath := getCertsPath()
	domainPath := filepath.Join(certsPath, "live", domain)

	if err := os.MkdirAll(domainPath, 0700); err != nil {
		return tryFallbackSave(domain, certs, err)
	}

	certPath := filepath.Join(domainPath, "cert.pem")
	if err := os.WriteFile(certPath, certs.Certificate, 0600); err != nil {
		return tryFallbackSave(domain, certs, err)
	}

	keyPath := filepath.Join(domainPath, "privkey.pem")
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		return tryFallbackSave(domain, certs, err)
	}

	issuerPath := filepath.Join(domainPath, "issuer.pem")
	if err := os.WriteFile(issuerPath, certs.IssuerCertificate, 0600); err != nil {
		return tryFallbackSave(domain, certs, err)
	}

	meta := certMeta{
		Source:     SourceAuto,
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
		Provider:   "cloudflare",
		UseStaging: false,
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(filepath.Join(domainPath, "cert.json"), metaData, 0600)

	return certPath, nil
}

func tryFallbackSave(domain string, certs *certificate.Resource, primaryErr error) (string, error) {
	fallbackPath := filepath.Join("db/certs", "live", domain)
	if err := os.MkdirAll(fallbackPath, 0700); err != nil {
		return "", fmt.Errorf("primary (%s) and fallback (db/certs) both failed: %v", primaryErr, err)
	}

	certPath := filepath.Join(fallbackPath, "cert.pem")
	if err := os.WriteFile(certPath, certs.Certificate, 0600); err != nil {
		return "", fmt.Errorf("primary (%s) and fallback failed: %v", primaryErr, err)
	}

	keyPath := filepath.Join(fallbackPath, "privkey.pem")
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		return "", fmt.Errorf("primary (%s) and fallback failed: %v", primaryErr, err)
	}

	issuerPath := filepath.Join(fallbackPath, "issuer.pem")
	if err := os.WriteFile(issuerPath, certs.IssuerCertificate, 0600); err != nil {
		return "", fmt.Errorf("primary (%s) and fallback failed: %v", primaryErr, err)
	}

	meta := certMeta{
		Source:     SourceAuto,
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
		Provider:   "cloudflare",
		UseStaging: false,
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(filepath.Join(fallbackPath, "cert.json"), metaData, 0600)

	return certPath, nil
}

func sanitizeEmail(email string) string {
	email = filepath.Clean(email)
	return email
}

func GetDNSProvider(provider string, credentials map[string]string) (interface{}, error) {
	switch provider {
	case "cloudflare":
		apiToken := credentials["api_token"]
		if apiToken == "" {
			return nil, fmt.Errorf("cloudflare API token required")
		}
		config := cloudflare.NewDefaultConfig()
		config.AuthToken = apiToken
		return cloudflare.NewDNSProviderConfig(config)
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", provider)
	}
}
