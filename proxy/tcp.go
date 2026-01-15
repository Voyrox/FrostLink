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
	ID         string `json:"id"`
	Domain     string `json:"domain,omitempty"`
	ListenPort int    `json:"listen_port"`
	Upstream   string `json:"upstream"`
	TLSMode    string `json:"tls_mode,omitempty"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	Enabled    bool   `json:"enabled"`
	MaxConns   int    `json:"max_conns"`
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
	Streams []StreamConfig         `json:"streams"`
	Stats   map[string]StreamStats `json:"stats,omitempty"`
}

var (
	streamsMu    sync.RWMutex
	streams      []StreamConfig
	streamsStats map[string]StreamStats
	streamsInit  bool
	listenerMap  map[int]*portListener
)

type portListener struct {
	listener net.Listener
	streams  []StreamConfig
	running  bool
	wg       sync.WaitGroup
}

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
			listenerMap = make(map[int]*portListener)
			streamsInit = true
			return
		}
		streams = []StreamConfig{}
		streamsStats = make(map[string]StreamStats)
		listenerMap = make(map[int]*portListener)
		streamsInit = true
		return
	}

	var sf streamsFile
	if err := json.Unmarshal(data, &sf); err != nil {
		streams = []StreamConfig{}
		streamsStats = make(map[string]StreamStats)
		listenerMap = make(map[int]*portListener)
		streamsInit = true
		return
	}

	streams = sf.Streams
	streamsStats = sf.Stats
	if streamsStats == nil {
		streamsStats = make(map[string]StreamStats)
	}
	listenerMap = make(map[int]*portListener)
	streamsInit = true
}

func saveStreams() {
	streamsMu.Lock()
	defer streamsMu.Unlock()
	saveStreamsUnlocked()
}

func saveStreamsUnlocked() {
	sf := streamsFile{
		Streams: streams,
		Stats:   streamsStats,
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

func StartStreamServer() error {
	loadStreams()
	streamsMu.RLock()
	streamsCopy := make([]StreamConfig, len(streams))
	copy(streamsCopy, streams)
	streamsMu.RUnlock()

	streamsMu.Lock()
	defer streamsMu.Unlock()

	listenerMap = make(map[int]*portListener)

	for _, s := range streamsCopy {
		if !s.Enabled {
			continue
		}
		if _, exists := listenerMap[s.ListenPort]; !exists {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.ListenPort))
			if err != nil {
				return fmt.Errorf("failed to listen on port %d: %w", s.ListenPort, err)
			}
			listenerMap[s.ListenPort] = &portListener{
				listener: ln,
				streams:  []StreamConfig{},
				running:  true,
			}
		}
		listenerMap[s.ListenPort].streams = append(listenerMap[s.ListenPort].streams, s)
	}

	for port, pl := range listenerMap {
		pl.wg.Add(1)
		go func(port int, pl *portListener) {
			defer pl.wg.Done()
			for pl.running {
				conn, err := pl.listener.Accept()
				if err != nil {
					if pl.running {
						ui.SystemLog("error", "tcp-accept", fmt.Sprintf("Accept error on port %d: %v", port, err))
					}
					continue
				}
				go pl.handleConnection(conn)
			}
		}(port, pl)
		ui.SystemLog("info", "tcp-proxy", fmt.Sprintf("Listening on port %d", port))
	}

	return nil
}

func StopStreamServer() {
	streamsMu.Lock()
	defer streamsMu.Unlock()

	for _, pl := range listenerMap {
		pl.running = false
		pl.listener.Close()
		pl.wg.Wait()
	}
	listenerMap = make(map[int]*portListener)
	ui.SystemLog("info", "tcp-proxy", "Stream server stopped")
}

func (pl *portListener) handleConnection(conn net.Conn) {
	defer conn.Close()

	var sni string
	var isTLS bool

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if n > 0 {
		if buf[0] == 0x16 {
			isTLS = true
			sni = extractSNIFromClientHello(buf[:n])
		}
	}

	var streamConfig *StreamConfig

	for _, cfg := range pl.streams {
		if !cfg.Enabled {
			continue
		}
		if cfg.Domain != "" {
			if MatchDomain(sni, cfg.Domain) {
				streamConfig = &cfg
				break
			}
		}
	}

	if streamConfig == nil && !isTLS {
		for _, cfg := range pl.streams {
			if !cfg.Enabled {
				continue
			}
			if cfg.Domain == "" {
				streamConfig = &cfg
				break
			}
		}
	}

	if streamConfig == nil {
		return
	}

	upConn, err := net.Dial("tcp", streamConfig.Upstream)
	if err != nil {
		return
	}
	defer upConn.Close()

	streamsMu.Lock()
	stats := streamsStats[streamConfig.ID]
	stats.Connections++
	stats.ActiveConns++
	stats.LastActive = time.Now()
	streamsStats[streamConfig.ID] = stats
	streamsMu.Unlock()

	if isTLS && streamConfig.TLSMode == "pass-through" && streamConfig.Domain != "" {
		copyBidirectional(conn, upConn, streamConfig.ID)
	} else if streamConfig.Domain != "" && streamConfig.TLSMode == "terminate" {
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
		copyBidirectional(tlsConn, upConn, streamConfig.ID)
	} else {
		copyBidirectional(conn, upConn, streamConfig.ID)
	}
}

func extractSNIFromClientHello(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	if data[0] != 0x16 {
		return ""
	}

	offset := 9
	if len(data) <= offset {
		return ""
	}

	if data[offset] != 0x01 {
		return ""
	}

	offset += 4 + 2 + 32
	if len(data) <= offset {
		return ""
	}

	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen
	if len(data) <= offset {
		return ""
	}

	cipherSuiteLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuiteLen
	if len(data) <= offset {
		return ""
	}

	compLen := int(data[offset])
	offset += 1 + compLen
	if len(data) <= offset {
		return ""
	}

	extLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	extEnd := offset + extLen

	for offset+4 <= extEnd && offset < len(data) {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0 {
			if offset+3 > len(data) {
				break
			}
			offset++
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
