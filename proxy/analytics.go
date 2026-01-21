package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const analyticsPath = "./db/domain_analytics.json"

type analyticsFile struct {
	Analytics map[string]*domainAnalytics `json:"analytics"`
	SavedAt   time.Time                   `json:"saved_at"`
}

var (
	analyticsSaveChan chan struct{}
	analyticsDone     chan struct{}
)

func initAnalyticsPersistence() {
	analyticsSaveChan = make(chan struct{}, 1)
	analyticsDone = make(chan struct{})

	loadAnalyticsFromDisk()

	go analyticsSaveLoop()
}

func analyticsSaveLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-analyticsSaveChan:
			saveAnalyticsToDisk()
		case <-ticker.C:
			saveAnalyticsToDisk()
		case <-analyticsDone:
			saveAnalyticsToDisk()
			return
		}
	}
}

func loadAnalyticsFromDisk() {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()

	data, err := os.ReadFile(analyticsPath)
	if err != nil {
		if !os.IsNotExist(err) {
		}
		return
	}

	var af analyticsFile
	if err := json.Unmarshal(data, &af); err != nil {
		return
	}

	for domain, da := range af.Analytics {
		if domain == "" {
			continue
		}
		domainAnalyticsM[domain] = da
	}
}

func saveAnalyticsToDisk() {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()

	af := analyticsFile{
		Analytics: make(map[string]*domainAnalytics),
		SavedAt:   time.Now(),
	}

	for domain, da := range domainAnalyticsM {
		if domain == "" {
			continue
		}
		af.Analytics[domain] = da
	}

	data, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		return
	}

	if err := os.MkdirAll(filepath.Dir(analyticsPath), 0755); err != nil {
		return
	}

	if err := os.WriteFile(analyticsPath, data, 0600); err != nil {
	}
}

func ShutdownAnalyticsPersistence() {
	if analyticsDone != nil {
		close(analyticsDone)
	}
}

func RequestAnalyticsSave() {
	select {
	case analyticsSaveChan <- struct{}{}:
	default:
	}
}

type CountryCount struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

type CountryBreakdown struct {
	TopCountries []CountryCount   `json:"top_countries"`
	ByCountry    map[string]int64 `json:"by_country"`
}

func GetDomainCountryBreakdown(domain string) CountryBreakdown {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()

	da, ok := domainAnalyticsM[domain]
	if !ok {
		return CountryBreakdown{
			TopCountries: []CountryCount{},
			ByCountry:    make(map[string]int64),
		}
	}

	countryCounts := make(map[string]int64)
	for ip, count := range da.IPs {
		country := lookupCountry(ip)
		countryCounts[country] += count
	}

	var topCountries []CountryCount
	for country, count := range countryCounts {
		topCountries = append(topCountries, CountryCount{Country: country, Count: count})
	}

	for i := 0; i < len(topCountries)-1; i++ {
		for j := i + 1; j < len(topCountries); j++ {
			if topCountries[j].Count > topCountries[i].Count {
				topCountries[i], topCountries[j] = topCountries[j], topCountries[i]
			}
		}
	}

	if len(topCountries) > 10 {
		topCountries = topCountries[:10]
	}

	return CountryBreakdown{
		TopCountries: topCountries,
		ByCountry:    countryCounts,
	}
}
