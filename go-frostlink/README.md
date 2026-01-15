# SparkProxy-Go (Gin)

A minimal Go/Gin implementation mirroring the SparkProxy dashboard and APIs. This scaffolds:

- `GET /`, `/login` → serves `default/login.html`
- Protected pages: `/dashboard`, `/dashboard/logs`, `/dashboard/tunnels`, `/sidebar`
- Static CSS: `/styles/*` → serves from `default/styles`
- APIs: `POST /api/login`, `GET /api/proxys`, `GET /api/system/stats`

This focuses on the dashboard. The reverse proxy on ports 80/443 can be added using `net/http` + `httputil.ReverseProxy` as a separate server; starting privileged ports may require root.

## Prerequisites
- Go 1.21+
- Env vars: `USER`, `PASSWORD` (for dashboard auth)
- Domain config files in `./domains/*.conf` (same format as Rust)

## Run
```bash
cd go-SparkProxy
GO111MODULE=on go mod tidy
go run .
```
Then open http://localhost:8080/ .

## Notes
- `POST /api/login` sets a `session` cookie and returns `{valid, session_id}` like the Rust service.
- `GET /api/proxys` parses `./domains` and returns configs; stats are zero until a reverse proxy is implemented.
- To implement reverse proxy, start additional servers on `:80` and `:443` (TLS using `ssl_certificate` + `ssl_certificate_key` per domain), and update `ProxyStatistics` accordingly.
