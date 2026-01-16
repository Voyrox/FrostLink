package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const profilerPath = "./db/domain_profiler.json"

type profilerFile struct {
	Domains map[string]bool `json:"domains"`
}

var (
	profilerMu     sync.RWMutex
	profilerCache  map[string]bool
	profilerLoaded bool
)

func loadProfilerConfig() {
	profilerMu.Lock()
	defer profilerMu.Unlock()
	if profilerLoaded {
		return
	}

	profilerCache = make(map[string]bool)
	data, err := os.ReadFile(profilerPath)
	if err != nil {
		if !os.IsNotExist(err) {
			profilerCache = make(map[string]bool)
		}
		profilerLoaded = true
		return
	}

	var pf profilerFile
	if err := json.Unmarshal(data, &pf); err != nil {
		profilerCache = make(map[string]bool)
		profilerLoaded = true
		return
	}

	for domain, enabled := range pf.Domains {
		profilerCache[strings.ToLower(domain)] = enabled
	}
	profilerLoaded = true
}

func IsProfilerEnabled(domain string) bool {
	loadProfilerConfig()
	profilerMu.RLock()
	defer profilerMu.RUnlock()
	return profilerCache[strings.ToLower(domain)]
}

func SetProfilerEnabled(domain string, enabled bool) error {
	loadProfilerConfig()

	profilerMu.Lock()
	defer profilerMu.Unlock()

	profilerCache[strings.ToLower(domain)] = enabled

	pf := profilerFile{
		Domains: profilerCache,
	}

	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(profilerPath), 0755); err != nil {
		return err
	}

	return os.WriteFile(profilerPath, data, 0600)
}

func GetAllProfilerStatus() map[string]bool {
	loadProfilerConfig()
	profilerMu.RLock()
	defer profilerMu.RUnlock()

	result := make(map[string]bool)
	for k, v := range profilerCache {
		result[k] = v
	}
	return result
}
