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
