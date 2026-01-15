# SparkProxy

SparkProxy is a powerful and flexible reverse proxy tool developed in Go. It's designed to route requests efficiently from public domains to local servers, supporting HTTP, HTTPS, and TCP traffic.

## Features

- HTTP/HTTPS reverse proxy
- TCP stream proxy (SMTP, IMAP, custom TCP)
- Web dashboard
- User authentication & sessions
- API tokens
- Audit logging
- Firewall (IP blocking, country bans)

## Getting Started

### Prerequisites

- Go 1.21+
- Linux (recommended), macOS, Windows

### Building

```bash
git clone https://github.com/Voyrox/SparkProxy.git
cd SparkProxy
go build -o SparkProxy main.go
```

### Running

1. **Create configuration files** in `./domains` directory
2. **Start the proxy:** `./SparkProxy`
3. **Access dashboard:** http://localhost:8080

Default credentials: `admin` / `admin`

### Configuration Files

Create `.conf` files in the `./domains` directory:

**HTTP/HTTPS Proxy:**
```plaintext
server: {
    domain: example.com
    location: localhost:3000

    connection: {
        AllowSSL: true
        AllowHTTP: true
    }
}

SSLCert: {
    ssl_certificate: /etc/letsencrypt/live/example.com/fullchain.pem
    ssl_certificate_key: /etc/letsencrypt/live/example.com/privkey.pem
}
```

**TCP Stream Proxy:**
```plaintext
server: {
    domain: smtp.example.com
    location: 192.168.1.60:25
    protocol: tcp
}
```

### Dashboard

SparkProxy includes a user-friendly dashboard for easy monitoring and management.

<p align="center">
    <img src="./public/img/dashboard-preview.png">
</p>

### Contributing

Feel free to open issues or submit pull requests. Contributions are welcome!

### License

See LICENSE file.
