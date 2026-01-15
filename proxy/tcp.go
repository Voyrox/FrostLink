package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SparkProxy/ui"
)

const streamsPath = "db/streams.json"

type StreamConfig struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Upstream string `json:"upstream"`
	Port     int    `json:"port"`
	TLSMode  string `json:"tls_mode"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	Enabled  bool   `json:"enabled"`
	MaxConns int    `json:"max_conns"`
}

type StreamStats struct {
	Connections   int64     `json:"connections"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	PPS           float64   `json:"pps"`
	ActiveConns   int       `json:"active_conns"`
	LastActive    time.Time `json:"last_active"`
	LastPPSUpdate time.Time `json:"last_pps_update"`
}

type streamsFile struct {
	Streams      []StreamConfig         `json:"streams"`
	ListenerPort int                    `json:"listener_port"`
	Stats        map[string]StreamStats `json:"stats,omitempty"`
}

var (
	streamsMu    sync.RWMutex
	streams      []StreamConfig
	streamsStats map[string]StreamStats
	streamsInit  bool
	listenerPort int
	tcpServer    *TCPServer
)

func init() {
	loadStreams()
}

func loadStreams() {
	if streamsInit {
		return
	}
	streamsMu.Lock()
	defer streamsMu.Unlock()
	if streamsInit {
		return
	}

	data, err := os.ReadFile(streamsPath)
	if err != nil {
		if os.IsNotExist(err) {
			streams = []StreamConfig{}
			streamsStats = make(map[string]StreamStats)
			listenerPort = 443
			streamsInit = true
			return
		}
		streams = []StreamConfig{}
		streamsStats = make(map[string]StreamStats)
		listenerPort = 443
		streamsInit = true
		return
	}

	var sf streamsFile
	if err := json.Unmarshal(data, &sf); err != nil {
		streams = []StreamConfig{}
		streamsStats = make(map[string]StreamStats)
		listenerPort = 443
		streamsInit = true
		return
	}

	streams = sf.Streams
	streamsStats = sf.Stats
	if streamsStats == nil {
		streamsStats = make(map[string]StreamStats)
	}
	listenerPort = sf.ListenerPort
	if listenerPort == 0 {
		listenerPort = 443
	}
	streamsInit = true
}

func saveStreams() {
	streamsMu.Lock()
	defer streamsMu.Unlock()
	saveStreamsUnlocked()
}

func saveStreamsUnlocked() {
	sf := streamsFile{
		Streams:      streams,
		ListenerPort: listenerPort,
		Stats:        streamsStats,
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(streamsPath), 0755); err != nil {
		return
	}
	os.WriteFile(streamsPath, data, 0600)
}

func MatchDomain(domain, pattern string) bool {
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(domain, suffix)
	}
	return false
}

func ListStreams() []StreamConfig {
	loadStreams()
	streamsMu.RLock()
	defer streamsMu.RUnlock()
	out := make([]StreamConfig, len(streams))
	copy(out, streams)
	return out
}

func GetStreamStats() map[string]StreamStats {
	loadStreams()
	streamsMu.RLock()
	defer streamsMu.RUnlock()
	out := make(map[string]StreamStats)
	for k, v := range streamsStats {
		out[k] = v
	}
	return out
}

func CreateStream(cfg StreamConfig) error {
	loadStreams()
	streamsMu.Lock()
	defer streamsMu.Unlock()

	streams = append(streams, cfg)
	if _, ok := streamsStats[cfg.ID]; !ok {
		streamsStats[cfg.ID] = StreamStats{LastPPSUpdate: time.Now()}
	}
	saveStreamsUnlocked()
	return nil
}

func UpdateStream(id string, cfg StreamConfig) error {
	loadStreams()
	streamsMu.Lock()
	defer streamsMu.Unlock()

	idx := -1
	for i, s := range streams {
		if s.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("stream not found")
	}

	streams[idx] = cfg
	saveStreamsUnlocked()
	return nil
}

func DeleteStream(id string) error {
	loadStreams()
	streamsMu.Lock()
	defer streamsMu.Unlock()

	idx := -1
	for i, s := range streams {
		if s.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("stream not found")
	}

	delete(streamsStats, id)
	streams = append(streams[:idx], streams[idx+1:]...)
	saveStreamsUnlocked()
	return nil
}

type TCPServer struct {
	listener net.Listener
	running  bool
	wg       sync.WaitGroup
}

func StartStreamServer(configs []StreamConfig, port int) error {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", port, err)
	}

	tcpServer = &TCPServer{
		listener: ln,
		running:  true,
	}

	tcpServer.wg.Add(1)
	go func() {
		defer tcpServer.wg.Done()
		for tcpServer.running {
			conn, err := ln.Accept()
			if err != nil {
				if tcpServer.running {
					ui.SystemLog("error", "tcp-accept", fmt.Sprintf("Accept error: %v", err))
				}
				continue
			}
			go tcpServer.handleConnection(conn, configs)
		}
	}()

	ui.SystemLog("info", "tcp-proxy", fmt.Sprintf("Listening on port %d", port))
	return nil
}

func StopStreamServer() {
	if tcpServer == nil {
		return
	}
	tcpServer.running = false
	tcpServer.listener.Close()
	tcpServer.wg.Wait()
	tcpServer = nil
	ui.SystemLog("info", "tcp-proxy", "Stopped")
}

func (s *TCPServer) handleConnection(conn net.Conn, configs []StreamConfig) {
	defer conn.Close()

	var sni string
	var isTLS bool

	// Peek at first bytes to detect TLS
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if n > 0 {
		// Check if it's a TLS record
		if buf[0] == 0x16 { // TLS record header
			isTLS = true
			sni = extractSNIFromClientHello(buf[:n])
		}
	}

	var upstream string
	var streamConfig *StreamConfig

	// Find matching stream
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		if MatchDomain(sni, cfg.Domain) {
			streamConfig = &cfg
			upstream = cfg.Upstream
			break
		}
	}

	if streamConfig == nil && !isTLS {
		// For non-TLS, try to match by pattern (could be wildcard without SNI)
		for _, cfg := range configs {
			if !cfg.Enabled {
				continue
			}
			if strings.HasPrefix(cfg.Domain, "*.") && sni == "" {
				streamConfig = &cfg
				upstream = cfg.Upstream
				break
			}
		}
	}

	if streamConfig == nil {
		return
	}

	// Connect to upstream
	upConn, err := net.Dial("tcp", upstream)
	if err != nil {
		return
	}
	defer upConn.Close()

	// Update stats
	streamsMu.Lock()
	stats := streamsStats[streamConfig.ID]
	stats.Connections++
	stats.ActiveConns++
	stats.LastActive = time.Now()
	streamsStats[streamConfig.ID] = stats
	streamsMu.Unlock()

	// Handle TLS pass-through or termination
	if isTLS && streamConfig.TLSMode == "pass-through" {
		// TLS pass-through: just copy bytes
		copyBidirectional(conn, upConn, streamConfig.ID)
	} else {
		// TLS termination or plain TCP
		if isTLS {
			tlsConfig := &tls.Config{}
			if streamConfig.CertFile != "" && streamConfig.KeyFile != "" {
				cert, err := tls.LoadX509KeyPair(streamConfig.CertFile, streamConfig.KeyFile)
				if err == nil {
					tlsConfig.Certificates = []tls.Certificate{cert}
				}
			}
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
		}
		copyBidirectional(conn, upConn, streamConfig.ID)
	}
}

func extractSNIFromClientHello(data []byte) string {
	// Simple TLS ClientHello parser
	// Check if it's a TLS record
	if len(data) < 5 {
		return ""
	}
	recordType := data[0]
	if recordType != 0x16 { // Handshake
		return ""
	}

	// Skip record header (5 bytes) and handshake header (4 bytes)
	offset := 9
	if len(data) <= offset {
		return ""
	}

	// Parse handshake message
	msgType := data[offset]
	if msgType != 0x01 { // ClientHello
		return ""
	}

	// Skip handshake header (4 bytes) + client version (2 bytes) + random (32 bytes)
	offset += 4 + 2 + 32
	if len(data) <= offset {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen
	if len(data) <= offset {
		return ""
	}

	// Skip cipher suites
	cipherSuiteLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuiteLen
	if len(data) <= offset {
		return ""
	}

	// Skip compression methods
	compLen := int(data[offset])
	offset += 1 + compLen
	if len(data) <= offset {
		return ""
	}

	// Parse extensions
	extLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	extEnd := offset + extLen

	for offset+4 <= extEnd && offset < len(data) {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0 { // server_name extension
			// Skip name type (1 byte) and name length (2 bytes)
			if offset+3 > len(data) {
				break
			}
			offset++ // name type
			nameLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			if offset+nameLen > len(data) {
				break
			}
			return string(data[offset : offset+nameLen])
		}

		offset += extLen
	}

	return ""
}

func copyBidirectional(conn1, conn2 net.Conn, streamID string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn1, conn2)
		updateStreamStats(streamID, n, 0)
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn2, conn1)
		updateStreamStats(streamID, 0, n)
	}()

	wg.Wait()

	// Decrement active connections
	streamsMu.Lock()
	if stats, ok := streamsStats[streamID]; ok {
		stats.ActiveConns--
		streamsStats[streamID] = stats
	}
	streamsMu.Unlock()
}

func updateStreamStats(streamID string, bytesIn, bytesOut int64) {
	streamsMu.Lock()
	defer streamsMu.Unlock()

	stats, ok := streamsStats[streamID]
	if !ok {
		return
	}

	stats.BytesIn += bytesIn
	stats.BytesOut += bytesOut
	stats.LastActive = time.Now()

	// Update PPS
	now := time.Now()
	elapsed := now.Sub(stats.LastPPSUpdate)
	if elapsed >= time.Second {
		totalBytes := stats.BytesIn + stats.BytesOut
		stats.PPS = float64(totalBytes) / elapsed.Seconds()
		stats.LastPPSUpdate = now
	}

	streamsStats[streamID] = stats
	saveStreamsUnlocked()
}
