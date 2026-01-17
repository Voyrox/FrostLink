package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sparkproxy_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"domain", "method", "status"},
	)

	BytesInTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sparkproxy_bytes_in_total",
			Help: "Total bytes uploaded",
		},
		[]string{"domain"},
	)

	BytesOutTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sparkproxy_bytes_out_total",
			Help: "Total bytes downloaded",
		},
		[]string{"domain"},
	)

	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sparkproxy_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"domain"},
	)

	FirewallBlocksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sparkproxy_firewall_blocks_total",
			Help: "Total number of firewall blocked requests",
		},
		[]string{"domain"},
	)

	ActiveDomains = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sparkproxy_active_domains",
			Help: "Number of configured domains",
		},
	)

	UptimeSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sparkproxy_uptime_seconds",
			Help: "Server uptime in seconds",
		},
	)
)

func IncRequests(domain, method string, statusCode int) {
	RequestsTotal.WithLabelValues(domain, method, itoa(statusCode)).Inc()
}

func AddBytesIn(domain string, bytes int64) {
	BytesInTotal.WithLabelValues(domain).Add(float64(bytes))
}

func AddBytesOut(domain string, bytes int64) {
	BytesOutTotal.WithLabelValues(domain).Add(float64(bytes))
}

func ObserveDuration(domain string, durationSeconds float64) {
	RequestDuration.WithLabelValues(domain).Observe(durationSeconds)
}

func IncFirewallBlocks(domain string) {
	FirewallBlocksTotal.WithLabelValues(domain).Inc()
}

func SetActiveDomains(count int) {
	ActiveDomains.Set(float64(count))
}

func SetUptime(seconds float64) {
	UptimeSeconds.Set(seconds)
}
