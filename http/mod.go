package http

import (
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	filepkg "SparkProxy/file"
	logger "SparkProxy/logger"
	sslpkg "SparkProxy/ssl"

	"github.com/oschwald/geoip2-golang"
)

type domainStats struct {
	Domain        string
	DataInTotal   int64
	DataOutTotal  int64
	TotalRequests int64
	LastIP        string
	LastCountry   string
	LastPath      string
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

type DomainStats struct {
	Domain        string `json:"domain"`
	DataInTotal   int64  `json:"data_in_total"`
	DataOutTotal  int64  `json:"data_out_total"`
	TotalRequests int64  `json:"total_requests"`
	LastIP        string `json:"last_ip"`
	LastCountry   string `json:"last_country"`
	LastPath      string `json:"last_path"`
}

var (
	statsMu      sync.Mutex
	domainStatsM = make(map[string]*domainStats)
	geoDBOnce    sync.Once
	geoDB        *geoip2.Reader

	cidrOnce sync.Once
	ipv4CIDR []ipRange
	ipv6CIDR []ipRange

	logsMu      sync.Mutex
	requestLogs []RequestLog

	indexTplOnce sync.Once
	indexTpl     *template.Template
)

type ipRange struct {
	network *net.IPNet
	country string
}

type loggingResponseWriter struct {
	stdhttp.ResponseWriter
	bytesWritten int64
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytesWritten += int64(n)
	return n, err
}

func clientIP(r *stdhttp.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func initGeoDB() {
	path := os.Getenv("GEOIP_DB_PATH")
	if path == "" {
		return
	}
	db, err := geoip2.Open(path)
	if err != nil {
		logger.SystemLog("error", "geoip", fmt.Sprintf("Failed to open GeoIP DB %s: %v", path, err))
		return
	}
	geoDB = db
}

func lookupCountry(ip string) string {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return "UNKNOWN"
	}

	if country := lookupCountryGeoIP(netIP); country != "" {
		return country
	}
	if country := lookupCountryCIDR(netIP); country != "" {
		return country
	}
	return "UNKNOWN"
}

func lookupCountryGeoIP(netIP net.IP) string {
	geoDBOnce.Do(initGeoDB)
	if geoDB == nil {
		return "UNKNOWN"
	}
	rec, err := geoDB.Country(netIP)
	if err != nil || rec == nil {
		return "UNKNOWN"
	}
	if rec.Country.IsoCode != "" {
		return rec.Country.IsoCode
	}
	if name, ok := rec.Country.Names["en"]; ok && name != "" {
		return name
	}
	return ""
}

func initCIDRDB() {
	loadCIDRFile("./db/IPV4.CIDR.CSV", true)
	loadCIDRFile("./db/IPV6.CIDR.CSV", false)
}

func loadCIDRFile(path string, isIPv4 bool) {
	f, err := os.Open(path)
	if err != nil {
		logger.SystemLog("error", "cidrdb", fmt.Sprintf("Failed to open CIDR DB %s: %v", path, err))
		return
	}
	defer f.Close()

	r := csv.NewReader(f)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.SystemLog("error", "cidrdb", fmt.Sprintf("Error reading CIDR DB %s: %v", path, err))
			break
		}
		if len(rec) < 2 {
			continue
		}
		cidr := rec[0]
		country := rec[1]
		_, network, err := net.ParseCIDR(strings.TrimSpace(strings.Trim(cidr, "\"")))
		if err != nil {
			continue
		}
		ir := ipRange{network: network, country: strings.TrimSpace(strings.Trim(country, "\""))}
		if isIPv4 {
			ipv4CIDR = append(ipv4CIDR, ir)
		} else {
			ipv6CIDR = append(ipv6CIDR, ir)
		}
	}
}

func lookupCountryCIDR(netIP net.IP) string {
	cidrOnce.Do(initCIDRDB)
	if len(ipv4CIDR) == 0 && len(ipv6CIDR) == 0 {
		return ""
	}
	isIPv4 := netIP.To4() != nil
	if isIPv4 {
		for _, r := range ipv4CIDR {
			if r.network.Contains(netIP) && r.country != "" {
				return r.country
			}
		}
	} else {
		for _, r := range ipv6CIDR {
			if r.network.Contains(netIP) && r.country != "" {
				return r.country
			}
		}
	}
	return ""
}

func logRequestStats(cfg filepkg.Config, r *stdhttp.Request, bytesIn, bytesOut int64) {
	ip := clientIP(r)
	country := lookupCountry(ip)
	domain := cfg.Domain
	path := r.URL.Path
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}

	statsMu.Lock()
	ds, ok := domainStatsM[domain]
	if !ok {
		ds = &domainStats{Domain: domain}
		domainStatsM[domain] = ds
	}
	ds.DataInTotal += bytesIn
	ds.DataOutTotal += bytesOut
	ds.TotalRequests++
	ds.LastIP = ip
	ds.LastCountry = country
	ds.LastPath = path
	currentTotal := ds.TotalRequests
	totalIn := ds.DataInTotal
	totalOut := ds.DataOutTotal
	statsMu.Unlock()

	logsMu.Lock()
	const maxRequestLogs = 1000
	if len(requestLogs) >= maxRequestLogs {
		requestLogs = requestLogs[1:]
	}
	requestLogs = append(requestLogs, RequestLog{
		Timestamp: time.Now(),
		Action:    "Allow",
		IP:        ip,
		Country:   country,
		Host:      domain,
		Path:      path,
		Method:    r.Method,
	})
	logsMu.Unlock()

	debugLog := os.Getenv("DEBUG")
	if debugLog == "true" {
		logger.SystemLog("info", "proxy-request",
			fmt.Sprintf("proto=%s domain=%s ip=%s country=%s path=%s data_in=%d data_out=%d total_requests=%d total_in=%d total_out=%d",
				proto, domain, ip, country, path, bytesIn, bytesOut, currentTotal, totalIn, totalOut))
	}
}

func GetDomainStats() []DomainStats {
	statsMu.Lock()
	defer statsMu.Unlock()

	res := make([]DomainStats, 0, len(domainStatsM))
	for _, ds := range domainStatsM {
		res = append(res, DomainStats{
			Domain:        ds.Domain,
			DataInTotal:   ds.DataInTotal,
			DataOutTotal:  ds.DataOutTotal,
			TotalRequests: ds.TotalRequests,
			LastIP:        ds.LastIP,
			LastCountry:   ds.LastCountry,
			LastPath:      ds.LastPath,
		})
	}
	return res
}

func StartProxy(configs []filepkg.Config) error {
	addr := os.Getenv("PROXY_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		host := r.Host
		cfg, ok := findConfigByHost(configs, host)
		if !ok {
			serveIndexPage(w, r)
			return
		}
		if !cfg.AllowHTTP {
			w.WriteHeader(stdhttp.StatusForbidden)
			_, _ = w.Write([]byte("HTTP disabled for this domain"))
			return
		}

		upstream := cfg.Location
		if upstream == "" {
			w.WriteHeader(stdhttp.StatusBadGateway)
			_, _ = w.Write([]byte("Upstream not configured"))
			return
		}

		targetURL, err := url.Parse("http://" + strings.TrimSpace(upstream))
		if err != nil {
			w.WriteHeader(stdhttp.StatusBadGateway)
			_, _ = w.Write([]byte("Invalid upstream: " + err.Error()))
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}

		lrw := &loggingResponseWriter{ResponseWriter: w}
		var bytesIn int64
		if r.ContentLength > 0 {
			bytesIn = r.ContentLength
		}

		proxy.Director = func(req *stdhttp.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		proxy.ErrorHandler = func(w stdhttp.ResponseWriter, req *stdhttp.Request, e error) {
			w.WriteHeader(stdhttp.StatusBadGateway)
			_, _ = w.Write([]byte("Proxy error: " + e.Error()))
		}

		proxy.ServeHTTP(lrw, r)
		logRequestStats(cfg, r, bytesIn, lrw.bytesWritten)
	})

	logger.SystemLog("info", "http-proxy", fmt.Sprintf("Listening on %s", addr))
	go sslpkg.StartTLSProxy(configs, mux)
	return stdhttp.ListenAndServe(addr, mux)
}

func findConfigByHost(configs []filepkg.Config, host string) (filepkg.Config, bool) {
	name := host
	if i := strings.IndexByte(name, ':'); i > -1 {
		name = name[:i]
	}
	for _, c := range configs {
		if strings.EqualFold(c.Domain, name) {
			return c, true
		}
	}
	return filepkg.Config{}, false
}

// GetRequestLogs returns a snapshot of recent request logs for the API.
func GetRequestLogs() []RequestLog {
	logsMu.Lock()
	defer logsMu.Unlock()

	out := make([]RequestLog, len(requestLogs))
	copy(out, requestLogs)
	return out
}

// serveIndexPage renders the default index.tmpl when no domain config matches.
func serveIndexPage(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	indexTplOnce.Do(func() {
		var err error
		indexTpl, err = template.ParseFiles("./views/index.tmpl")
		if err != nil {
			logger.SystemLog("error", "http-index", fmt.Sprintf("Failed to parse index.tmpl: %v", err))
		}
	})

	if indexTpl == nil {
		w.WriteHeader(stdhttp.StatusNotFound)
		_, _ = w.Write([]byte("<html><body><h1>404 Not Found</h1></body></html>"))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTpl.ExecuteTemplate(w, "index", nil); err != nil {
		logger.SystemLog("error", "http-index", fmt.Sprintf("Failed to execute index.tmpl: %v", err))
	}
}
