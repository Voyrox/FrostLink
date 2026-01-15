package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

const auditLogsPath = "db/audit_logs.json"

type AuditLog struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor"`
	IP        string            `json:"ip"`
	UserAgent string            `json:"user_agent"`
	Resource  string            `json:"resource"`
	Status    string            `json:"status"`
	Details   map[string]string `json:"details,omitempty"`
}

type auditLogFile struct {
	Logs []AuditLog `json:"logs"`
}

var (
	logsMu sync.Mutex
	logs   []AuditLog
)

func init() {
	loadLogs()
	go cleanupRoutine()
}

func loadLogs() {
	logsMu.Lock()
	defer logsMu.Unlock()

	data, err := os.ReadFile(auditLogsPath)
	if err != nil {
		if os.IsNotExist(err) {
			logs = []AuditLog{}
			return
		}
		logs = []AuditLog{}
		return
	}

	var af auditLogFile
	if err := json.Unmarshal(data, &af); err != nil {
		logs = []AuditLog{}
		return
	}

	cutoff := time.Now().AddDate(0, 0, -30)
	var validLogs []AuditLog
	for _, log := range af.Logs {
		if log.Timestamp.After(cutoff) {
			validLogs = append(validLogs, log)
		}
	}
	logs = validLogs
}

func saveLogs() {
	logsMu.Lock()
	defer logsMu.Unlock()
	saveLogsUnlocked()
}

func saveLogsUnlocked() {
	data, err := json.MarshalIndent(auditLogFile{Logs: logs}, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(auditLogsPath), 0o755); err != nil {
		return
	}
	os.WriteFile(auditLogsPath, data, 0o600)
}

func cleanupRoutine() {
	for {
		time.Sleep(time.Hour)
		logsMu.Lock()
		cutoff := time.Now().AddDate(0, 0, -30)
		var validLogs []AuditLog
		var removed int
		for _, log := range logs {
			if log.Timestamp.After(cutoff) {
				validLogs = append(validLogs, log)
			} else {
				removed++
			}
		}
		if removed > 0 {
			logs = validLogs
			saveLogsUnlocked()
		}
		logsMu.Unlock()
	}
}

func Log(action, actor, ip, userAgent, resource, status string, details map[string]string) {
	logsMu.Lock()
	newLog := AuditLog{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Actor:     actor,
		IP:        ip,
		UserAgent: userAgent,
		Resource:  resource,
		Status:    status,
		Details:   details,
	}
	logs = append(logs, newLog)
	logsMu.Unlock()
	saveLogs()
}

func List(actionFilter, actorFilter string, limit int) []AuditLog {
	logsMu.Lock()
	defer logsMu.Unlock()

	result := make([]AuditLog, 0, len(logs))
	for _, log := range logs {
		if actionFilter != "" && log.Action != actionFilter {
			continue
		}
		if actorFilter != "" && log.Actor != actorFilter {
			continue
		}
		result = append(result, log)
	}

	if limit > 0 && len(result) > limit {
		return result[len(result)-limit:]
	}
	return result
}

func GetStats() (total, last24h int) {
	logsMu.Lock()
	defer logsMu.Unlock()

	now := time.Now()
	last24hCutoff := now.Add(-24 * time.Hour)

	for _, log := range logs {
		total++
		if log.Timestamp.After(last24hCutoff) {
			last24h++
		}
	}
	return total, last24h
}
