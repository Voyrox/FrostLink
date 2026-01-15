package core

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

type FirewallRules struct {
	BannedIPs       []string `json:"banned_ips"`
	BannedCountries []string `json:"banned_countries"`
}

var (
	firewallMu     sync.RWMutex
	firewallLoaded bool
	firewallRules  FirewallRules
	firewallPath   = filepath.Join(".", "db", "firewall.json")
)

func loadFirewall() {
	if firewallLoaded {
		return
	}
	firewallMu.Lock()
	defer firewallMu.Unlock()
	if firewallLoaded {
		return
	}
	b, err := os.ReadFile(firewallPath)
	if err != nil {
		if os.IsNotExist(err) {
			firewallRules = FirewallRules{}
			firewallLoaded = true
			return
		}
		firewallRules = FirewallRules{}
		firewallLoaded = true
		return
	}
	var r FirewallRules
	if err := json.Unmarshal(b, &r); err != nil {
		firewallRules = FirewallRules{}
		firewallLoaded = true
		return
	}
	dedupeAndSortFirewall(&r)
	firewallRules = r
	firewallLoaded = true
}

func saveFirewallLocked() error {
	data, err := json.MarshalIndent(firewallRules, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(firewallPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(firewallPath, data, 0600)
}

func dedupeAndSortFirewall(r *FirewallRules) {
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

func ListFirewallRules() FirewallRules {
	loadFirewall()
	firewallMu.RLock()
	defer firewallMu.RUnlock()
	out := firewallRules
	out.BannedIPs = append([]string(nil), firewallRules.BannedIPs...)
	out.BannedCountries = append([]string(nil), firewallRules.BannedCountries...)
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

func BanIP(ip string) error {
	loadFirewall()
	norm, err := normalizeIP(ip)
	if err != nil {
		return err
	}
	firewallMu.Lock()
	defer firewallMu.Unlock()
	for _, existing := range firewallRules.BannedIPs {
		if existing == norm {
			return nil
		}
	}
	firewallRules.BannedIPs = append(firewallRules.BannedIPs, norm)
	dedupeAndSortFirewall(&firewallRules)
	return saveFirewallLocked()
}

func BanIPs(ips []string) (int, error) {
	if len(ips) == 0 {
		return 0, errors.New("no ips provided")
	}
	loadFirewall()
	firewallMu.Lock()
	defer firewallMu.Unlock()

	added := 0
	for _, ip := range ips {
		norm, err := normalizeIP(ip)
		if err != nil {
			continue
		}
		exists := false
		for _, existing := range firewallRules.BannedIPs {
			if existing == norm {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		firewallRules.BannedIPs = append(firewallRules.BannedIPs, norm)
		added++
	}
	if added == 0 {
		return 0, errors.New("no valid ips to add")
	}
	dedupeAndSortFirewall(&firewallRules)
	if err := saveFirewallLocked(); err != nil {
		return 0, err
	}
	return added, nil
}

func BanCountry(code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return errors.New("country code is empty")
	}
	loadFirewall()
	firewallMu.Lock()
	defer firewallMu.Unlock()
	for _, existing := range firewallRules.BannedCountries {
		if existing == code {
			return nil
		}
	}
	firewallRules.BannedCountries = append(firewallRules.BannedCountries, code)
	dedupeAndSortFirewall(&firewallRules)
	return saveFirewallLocked()
}

func BanCountries(codes []string) (int, error) {
	if len(codes) == 0 {
		return 0, errors.New("no country codes provided")
	}
	loadFirewall()
	firewallMu.Lock()
	defer firewallMu.Unlock()

	added := 0
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		exists := false
		for _, existing := range firewallRules.BannedCountries {
			if existing == c {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		firewallRules.BannedCountries = append(firewallRules.BannedCountries, c)
		added++
	}
	if added == 0 {
		return 0, errors.New("no valid country codes to add")
	}
	dedupeAndSortFirewall(&firewallRules)
	if err := saveFirewallLocked(); err != nil {
		return 0, err
	}
	return added, nil
}

func IsBlocked(ip, country string) bool {
	loadFirewall()
	firewallMu.RLock()
	defer firewallMu.RUnlock()

	if ip != "" {
		if norm, err := normalizeIP(ip); err == nil {
			for _, b := range firewallRules.BannedIPs {
				if b == norm {
					return true
				}
			}
		}
	}

	if country != "" {
		c := strings.ToUpper(strings.TrimSpace(country))
		for _, b := range firewallRules.BannedCountries {
			if b == c {
				return true
			}
		}
	}

	return false
}

func UnbanIP(ip string) error {
	loadFirewall()
	norm, err := normalizeIP(ip)
	if err != nil {
		return err
	}
	firewallMu.Lock()
	defer firewallMu.Unlock()

	filtered := make([]string, 0, len(firewallRules.BannedIPs))
	for _, existing := range firewallRules.BannedIPs {
		if existing != norm {
			filtered = append(filtered, existing)
		}
	}
	firewallRules.BannedIPs = filtered
	dedupeAndSortFirewall(&firewallRules)
	return saveFirewallLocked()
}

func UnbanCountry(code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return errors.New("country code is empty")
	}
	loadFirewall()
	firewallMu.Lock()
	defer firewallMu.Unlock()

	filtered := make([]string, 0, len(firewallRules.BannedCountries))
	for _, existing := range firewallRules.BannedCountries {
		if existing != code {
			filtered = append(filtered, existing)
		}
	}
	firewallRules.BannedCountries = filtered
	dedupeAndSortFirewall(&firewallRules)
	return saveFirewallLocked()
}

func GetFirewallStats() (ipCount, countryCount int) {
	loadFirewall()
	firewallMu.RLock()
	defer firewallMu.RUnlock()
	return len(firewallRules.BannedIPs), len(firewallRules.BannedCountries)
}
