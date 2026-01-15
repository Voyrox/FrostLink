package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

const auditLogsPath = "db/audit_logs.json"
const requestLogsPath = "db/request_logs.json"

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
	auditLogsMu sync.Mutex
	auditLogs   []AuditLog
	auditInit   bool
)

func initAudit() {
	if auditInit {
		return
	}
	auditLogsMu.Lock()
	defer auditLogsMu.Unlock()
	if auditInit {
		return
	}

	data, err := os.ReadFile(auditLogsPath)
	if err != nil {
		if os.IsNotExist(err) {
			auditLogs = []AuditLog{}
			auditInit = true
			return
		}
		auditLogs = []AuditLog{}
		auditInit = true
		return
	}

	var af auditLogFile
	if err := json.Unmarshal(data, &af); err != nil {
		auditLogs = []AuditLog{}
		auditInit = true
		return
	}

	cutoff := time.Now().AddDate(0, 0, -30)
	var validLogs []AuditLog
	for _, log := range af.Logs {
		if log.Timestamp.After(cutoff) {
			validLogs = append(validLogs, log)
		}
	}
	auditLogs = validLogs
	auditInit = true
}

func saveAuditLogs() {
	auditLogsMu.Lock()
	defer auditLogsMu.Unlock()
	saveAuditLogsUnlocked()
}

func saveAuditLogsUnlocked() {
	data, err := json.MarshalIndent(auditLogFile{Logs: auditLogs}, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(auditLogsPath), 0755); err != nil {
		return
	}
	os.WriteFile(auditLogsPath, data, 0600)
}

func LogAudit(action, actor, ip, userAgent, resource, status string, details map[string]string) {
	auditLogsMu.Lock()
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
	auditLogs = append(auditLogs, newLog)
	auditLogsMu.Unlock()
	saveAuditLogs()
}

func ListAuditLogs(actionFilter, actorFilter string, limit int) []AuditLog {
	initAudit()
	auditLogsMu.Lock()
	defer auditLogsMu.Unlock()

	result := make([]AuditLog, 0, len(auditLogs))
	for _, log := range auditLogs {
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

type PaginatedAuditResponse struct {
	Logs       []AuditLog `json:"logs"`
	Total      int        `json:"total"`
	Page       int        `json:"page"`
	Limit      int        `json:"limit"`
	TotalPages int        `json:"total_pages"`
	Last24h    int        `json:"last_24h"`
}

func ListAuditLogsPaginated(actionFilter, actorFilter string, page, limit int) PaginatedAuditResponse {
	initAudit()
	auditLogsMu.Lock()
	defer auditLogsMu.Unlock()

	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	filtered := make([]AuditLog, 0, len(auditLogs))
	for _, log := range auditLogs {
		if actionFilter != "" && log.Action != actionFilter {
			continue
		}
		if actorFilter != "" && log.Actor != actorFilter {
			continue
		}
		filtered = append(filtered, log)
	}

	total := len(filtered)
	totalPages := (total + limit - 1) / limit

	offset := (page - 1) * limit
	var logs []AuditLog
	if offset < total {
		end := offset + limit
		if end > total {
			end = total
		}
		logs = filtered[offset:end]
	}

	now := time.Now()
	last24hCutoff := now.Add(-24 * time.Hour)
	last24h := 0
	for _, log := range filtered {
		if log.Timestamp.After(last24hCutoff) {
			last24h++
		}
	}

	return PaginatedAuditResponse{
		Logs:       logs,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
		Last24h:    last24h,
	}
}

func GetAuditStats() (total, last24h int) {
	initAudit()
	auditLogsMu.Lock()
	defer auditLogsMu.Unlock()

	now := time.Now()
	last24hCutoff := now.Add(-24 * time.Hour)

	for _, log := range auditLogs {
		total++
		if log.Timestamp.After(last24hCutoff) {
			last24h++
		}
	}
	return total, last24h
}

type RequestLog struct {
	Timestamp time.Time
	Action    string
	IP        string
	Country   string
	Host      string
	Path      string
	Method    string
}

type requestLogFile struct {
	Logs []RequestLog `json:"logs"`
}

var (
	requestLogsMu sync.Mutex
	requestLogs   []RequestLog
	reqLogsInit   bool
)

func initRequestLogs() {
	if reqLogsInit {
		return
	}
	requestLogsMu.Lock()
	defer requestLogsMu.Unlock()
	if reqLogsInit {
		return
	}

	data, err := os.ReadFile(requestLogsPath)
	if err != nil {
		if os.IsNotExist(err) {
			requestLogs = []RequestLog{}
			reqLogsInit = true
			return
		}
		requestLogs = []RequestLog{}
		reqLogsInit = true
		return
	}

	var rf requestLogFile
	if err := json.Unmarshal(data, &rf); err != nil {
		requestLogs = []RequestLog{}
		reqLogsInit = true
		return
	}

	cutoff := time.Now().AddDate(0, 0, -8)
	var validLogs []RequestLog
	for _, log := range rf.Logs {
		if log.Timestamp.After(cutoff) {
			validLogs = append(validLogs, log)
		}
	}
	requestLogs = validLogs
	reqLogsInit = true
}

func saveRequestLogs() {
	requestLogsMu.Lock()
	defer requestLogsMu.Unlock()
	saveRequestLogsUnlocked()
}

func saveRequestLogsUnlocked() {
	data, err := json.MarshalIndent(requestLogFile{Logs: requestLogs}, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(requestLogsPath), 0755); err != nil {
		return
	}
	os.WriteFile(requestLogsPath, data, 0600)
}

func LogRequest(action, ip, country, host, path, method string) {
	requestLogsMu.Lock()
	const maxRequestLogs = 1000
	if len(requestLogs) >= maxRequestLogs {
		requestLogs = requestLogs[1:]
	}
	newLog := RequestLog{
		Timestamp: time.Now(),
		Action:    action,
		IP:        ip,
		Country:   country,
		Host:      host,
		Path:      path,
		Method:    method,
	}
	requestLogs = append(requestLogs, newLog)
	requestLogsMu.Unlock()
	saveRequestLogs()
}

func GetRequestLogs() []RequestLog {
	initRequestLogs()
	requestLogsMu.Lock()
	defer requestLogsMu.Unlock()

	out := make([]RequestLog, len(requestLogs))
	copy(out, requestLogs)
	return out
}

type PaginatedLogsResponse struct {
	Logs       []RequestLog `json:"logs"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	Limit      int          `json:"limit"`
	TotalPages int          `json:"total_pages"`
}

func GetRequestLogsPaginated(page, limit int) PaginatedLogsResponse {
	initRequestLogs()
	requestLogsMu.Lock()
	defer requestLogsMu.Unlock()

	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	total := len(requestLogs)
	totalPages := (total + limit - 1) / limit

	offset := (page - 1) * limit
	end := offset + limit
	if end > total {
		end = total
	}

	var logs []RequestLog
	if offset < total {
		logs = requestLogs[offset:end]
	}

	return PaginatedLogsResponse{
		Logs:       logs,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
	}
}
