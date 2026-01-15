package firewall

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Rules struct {
	BannedIPs       []string `json:"banned_ips"`
	BannedCountries []string `json:"banned_countries"`
}

var (
	rulesMu     sync.RWMutex
	rulesLoaded bool
	rules       Rules
	rulesPath   = filepath.Join(".", "db", "firewall.json")
)

func load() {
	if rulesLoaded {
		return
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	if rulesLoaded {
		return
	}
	b, err := os.ReadFile(rulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			rules = Rules{}
			rulesLoaded = true
			return
		}
		rules = Rules{}
		rulesLoaded = true
		return
	}
	var r Rules
	if err := json.Unmarshal(b, &r); err != nil {
		rules = Rules{}
		rulesLoaded = true
		return
	}
	dedupeAndSort(&r)
	rules = r
	rulesLoaded = true
}

func saveLocked() error {
	// callers must hold rulesMu (write)
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rulesPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(rulesPath, data, 0o600)
}

func dedupeAndSort(r *Rules) {
	ipSet := make(map[string]struct{})
	for _, ip := range r.BannedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		ipSet[ip] = struct{}{}
	}
	r.BannedIPs = r.BannedIPs[:0]
	for ip := range ipSet {
		r.BannedIPs = append(r.BannedIPs, ip)
	}
	sort.Strings(r.BannedIPs)

	countrySet := make(map[string]struct{})
	for _, c := range r.BannedCountries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		countrySet[c] = struct{}{}
	}
	r.BannedCountries = r.BannedCountries[:0]
	for c := range countrySet {
		r.BannedCountries = append(r.BannedCountries, c)
	}
	sort.Strings(r.BannedCountries)
}

// List returns a copy of the current firewall rules.
func List() Rules {
	load()
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	out := rules
	out.BannedIPs = append([]string(nil), rules.BannedIPs...)
	out.BannedCountries = append([]string(nil), rules.BannedCountries...)
	return out
}

func normalizeIP(ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", errors.New("ip is empty")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", errors.New("invalid ip address")
	}
	return parsed.String(), nil
}

// BanIP adds a single IP (IPv4 or IPv6) to the banned list.
func BanIP(ip string) error {
	load()
	norm, err := normalizeIP(ip)
	if err != nil {
		return err
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	for _, existing := range rules.BannedIPs {
		if existing == norm {
			return nil
		}
	}
	rules.BannedIPs = append(rules.BannedIPs, norm)
	dedupeAndSort(&rules)
	return saveLocked()
}

// BanIPs adds many IPs at once, ignoring invalid entries.
func BanIPs(ips []string) (int, error) {
	if len(ips) == 0 {
		return 0, errors.New("no ips provided")
	}
	load()
	rulesMu.Lock()
	defer rulesMu.Unlock()

	added := 0
	for _, ip := range ips {
		norm, err := normalizeIP(ip)
		if err != nil {
			continue
		}
		exists := false
		for _, existing := range rules.BannedIPs {
			if existing == norm {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		rules.BannedIPs = append(rules.BannedIPs, norm)
		added++
	}
	if added == 0 {
		return 0, errors.New("no valid ips to add")
	}
	dedupeAndSort(&rules)
	if err := saveLocked(); err != nil {
		return 0, err
	}
	return added, nil
}

// BanCountry adds a 2-letter country code to the banned list.
func BanCountry(code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return errors.New("country code is empty")
	}
	load()
	rulesMu.Lock()
	defer rulesMu.Unlock()
	for _, existing := range rules.BannedCountries {
		if existing == code {
			return nil
		}
	}
	rules.BannedCountries = append(rules.BannedCountries, code)
	dedupeAndSort(&rules)
	return saveLocked()
}

// BanCountries adds multiple country codes at once.
func BanCountries(codes []string) (int, error) {
	if len(codes) == 0 {
		return 0, errors.New("no country codes provided")
	}
	load()
	rulesMu.Lock()
	defer rulesMu.Unlock()

	added := 0
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		exists := false
		for _, existing := range rules.BannedCountries {
			if existing == c {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		rules.BannedCountries = append(rules.BannedCountries, c)
		added++
	}
	if added == 0 {
		return 0, errors.New("no valid country codes to add")
	}
	dedupeAndSort(&rules)
	if err := saveLocked(); err != nil {
		return 0, err
	}
	return added, nil
}

// IsBlocked reports whether the given IP or country is blocked.
func IsBlocked(ip, country string) bool {
	load()
	rulesMu.RLock()
	defer rulesMu.RUnlock()

	if ip != "" {
		if norm, err := normalizeIP(ip); err == nil {
			for _, b := range rules.BannedIPs {
				if b == norm {
					return true
				}
			}
		}
	}

	if country != "" {
		c := strings.ToUpper(strings.TrimSpace(country))
		for _, b := range rules.BannedCountries {
			if b == c {
				return true
			}
		}
	}

	return false
}

// UnbanIP removes a single IP from the banned list.
func UnbanIP(ip string) error {
	load()
	norm, err := normalizeIP(ip)
	if err != nil {
		return err
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()

	filtered := make([]string, 0, len(rules.BannedIPs))
	for _, existing := range rules.BannedIPs {
		if existing != norm {
			filtered = append(filtered, existing)
		}
	}
	rules.BannedIPs = filtered
	dedupeAndSort(&rules)
	return saveLocked()
}

// UnbanCountry removes a country code from the banned list.
func UnbanCountry(code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return errors.New("country code is empty")
	}
	load()
	rulesMu.Lock()
	defer rulesMu.Unlock()

	filtered := make([]string, 0, len(rules.BannedCountries))
	for _, existing := range rules.BannedCountries {
		if existing != code {
			filtered = append(filtered, existing)
		}
	}
	rules.BannedCountries = filtered
	dedupeAndSort(&rules)
	return saveLocked()
}

// GetStats returns statistics about the firewall.
func GetStats() (ipCount, countryCount int) {
	load()
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	return len(rules.BannedIPs), len(rules.BannedCountries)
}
