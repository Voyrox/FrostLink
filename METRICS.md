# SparkProxy Prometheus Metrics

SparkProxy exposes a `/metrics` endpoint for Prometheus scraping with token-based authentication.

## Authentication

The metrics endpoint requires a Bearer token. Token is automatically generated on first run and stored in `./db/metrics_token`.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `METRICS_AUTH_TOKEN` | Set token manually (skips file) |
| `METRICS_TOKEN_FILE` | Custom path for token file (default: `./db/metrics_token`) |

### Example Request

```bash
TOKEN=$(cat ./db/metrics_token)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/metrics
```

## Prometheus Configuration

```yaml
scrape_configs:
  - job_name: sparkproxy
    metrics_path: /metrics
    static_configs:
      - targets: ['sparkproxy.example.com:8080']
    authorization:
      type: Bearer
      credentials_file: '/path/to/sparkproxy/db/metrics_token'
```

## Available Metrics

### HTTP Request Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sparkproxy_requests_total` | counter | domain, method, status | Total HTTP requests |
| `sparkproxy_request_duration_seconds` | histogram | domain | Request duration in seconds |
| `sparkproxy_bytes_in_total` | counter | domain | Total bytes uploaded |
| `sparkproxy_bytes_out_total` | counter | domain | Total bytes downloaded |

### Firewall Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sparkproxy_firewall_blocks_total` | counter | domain | Firewall blocked requests |

### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sparkproxy_active_domains` | gauge | Number of configured domains |
| `sparkproxy_uptime_seconds` | gauge | Server uptime in seconds |

### Go Runtime Metrics

| Metric | Description |
|--------|-------------|
| `go_goroutines` | Number of goroutines |
| `go_memstats_alloc_bytes` | Memory currently in use |
| `go_gc_duration_seconds` | GC pause times |
| `go_threads` | OS threads created |
| `process_cpu_seconds_total` | CPU time used |
| `process_resident_memory_bytes` | Memory RSS |
| `process_open_fds` | Open file descriptors |

## Example Queries

### Requests per domain

```promql
sum by (domain) (rate(sparkproxy_requests_total[5m]))
```

### Average request duration

```promql
rate(sparkproxy_request_duration_seconds_sum[5m]) / rate(sparkproxy_request_duration_seconds_count[5m])
```

### Firewall blocks rate

```promql
rate(sparkproxy_firewall_blocks_total[5m])
```

### Traffic volume

```promql
rate(sparkproxy_bytes_out_total[5m])  # bytes/sec outgoing
rate(sparkproxy_bytes_in_total[5m])   # bytes/sec incoming
```
