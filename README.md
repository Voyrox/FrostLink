# SparkProxy

A Go-based reverse proxy with HTTP/HTTPS support, TCP stream proxy, web dashboard, and domain management.

## Features

- HTTP/HTTPS reverse proxy
- TCP stream proxy (SMTP, IMAP, custom TCP)
- Web dashboard
- User authentication & sessions
- API tokens
- Audit logging
- Firewall (IP blocking, country bans)

## Quick Start

### Prerequisites

- Go 1.21+
- Linux (recommended), macOS, Windows

### Installation

#### Option A: Download Binary

```bash
wget https://github.com/anomalyco/SparkProxy/releases/latest/download/SparkProxy
chmod +x SparkProxy
./SparkProxy
```

#### Option B: Build from Source

```bash
git clone https://github.com/anomalyco/SparkProxy.git
cd SparkProxy
go build -o SparkProxy main.go
./SparkProxy
```

### Configuration

1. Copy `config.example.json` to `config.json`:

```bash
cp config.example.json config.json
```

2. Edit `config.json` with your settings

3. Start the proxy:

```bash
./SparkProxy
```

4. Access the dashboard at http://localhost:8080

**Default credentials:** `admin` / `admin` (change immediately!)

### First Run

On first run, SparkProxy creates:

- `db/users.json` - User database
- `db/domains.json` - Domain configurations
- `db/request_logs.json` - Request log storage
- `db/audit_logs.json` - Audit log storage
- `db/sessions.json` - Active sessions
- `db/csrf.json` - CSRF tokens
- `db/api_tokens.json` - API tokens

---

## Configuration

### Main Config (`config.json`)

```json
{
  "port": 8080,
  "admin_user": "admin",
  "admin_password": "changeme",
  "session_secret": "your-secret-here",
  "proxy_addr": ":8081",
  "tcp_proxies": [],
  "tcp_defaults": {
    "proxy_connect_timeout": "10s",
    "proxy_timeout": "1h",
    "health_check_interval": "30s",
    "max_fails": 3,
    "fail_timeout": "30s"
  }
}
```

### Domains (`db/domains.json`)

```json
{
  "domains": [
    {
      "domain": "example.com",
      "location": "192.168.1.100:8080",
      "allow_http": true
    }
  ]
}
```

### TCP Proxies (`config.json`)

```json
{
  "tcp_proxies": [
    {
      "name": "mailcow-smtp",
      "listen": "0.0.0.0:25",
      "upstream": "192.168.1.60:25"
    },
    {
      "name": "mailcow-imaps",
      "listen": "0.0.0.0:993",
      "upstream": "192.168.1.60:993",
      "tls": {
        "mode": "terminate",
        "cert_file": "/etc/ssl/certs/mailcow.crt",
        "key_file": "/etc/ssl/private/mailcow.key"
      }
    }
  ]
}
```

---

## TCP Proxy Guide

### Overview

SparkProxy can proxy any TCP traffic, not just HTTP. This is useful for:

- SMTP (25, 465, 587)
- IMAP (143, 993)
- POP3 (110, 995)
- Custom TCP services

### Examples

#### Basic TCP Proxy

```json
{
  "name": "my-smtp",
  "listen": "0.0.0.0:25",
  "upstream": "192.168.1.10:25"
}
```

#### TLS Termination

```json
{
  "name": "secure-imap",
  "listen": "0.0.0.0:993",
  "upstream": "192.168.1.10:143",
  "tls": {
    "mode": "terminate",
    "cert_file": "/etc/ssl/certs/imap.crt",
    "key_file": "/etc/ssl/private/imap.key"
  }
}
```

#### TLS Pass-Through with SNI Routing

```json
{
  "name": "sni-router",
  "listen": "0.0.0.0:443",
  "tls": {
    "mode": "pass-through"
  },
  "sni_routes": [
    {"host": "smtp.example.com", "upstream": "192.168.1.10:25"},
    {"host": "imap.example.com", "upstream": "192.168.1.10:993"}
  ]
}
```

---

## API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/_auth/login` | POST | User login |
| `/_auth/logout` | POST | User logout |
| `/_auth/csrf` | POST | Get CSRF token |

### Users (Admin)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/users` | GET | List users |
| `/api/users` | POST | Create user |
| `/api/users/{username}` | PUT | Update user |
| `/api/users/{username}` | DELETE | Delete user |

### Domains

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/domains` | GET | List domains |
| `/api/domains` | POST | Create domain |
| `/api/domains/{domain}` | PUT | Update domain |
| `/api/domains/{domain}` | DELETE | Delete domain |

### Logs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/logs` | GET | Request logs (paginated) |
| `/api/audit` | GET | Audit logs (paginated) |

### API Tokens

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tokens` | GET | List tokens |
| `/api/tokens` | POST | Create token |
| `/api/tokens/{id}` | DELETE | Revoke token |

---

## Development

### Building

```bash
go build -o SparkProxy main.go
```

### Testing

```bash
go test ./...
```

### Project Structure

```
SparkProxy/
├── main.go           # Bootstrap and router
├── proxy/            # HTTP/HTTPS/TCP proxy logic
├── core/             # Config, auth, firewall, audit
├── ui/               # Logging and templates
└── views/            # Dashboard templates
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROXY_ADDR` | Proxy listen address | `:8081` |
| `GEOIP_DB_PATH` | Path to GeoIP database | - |
| `DEBUG` | Enable debug logging | - |

---

## License

SparkProxy is open-source software. See LICENSE file for details.
