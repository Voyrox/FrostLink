# SparkProxy

SparkProxy is a powerful and flexible reverse proxy tool developed in go. It's designed to route requests efficiently from public domains to local servers, supporting both HTTP and HTTPS traffic. ArcticArch is particularly useful for exposing local development servers to the internet or for setting up a custom routing scheme in a microservices architecture.


# 🚀 Features
> [!TIP]
> - **Support for HTTP and HTTPS**: Handles both unencrypted and encrypted traffic, with easy SSL/TLS setup.
> - **Dynamic Configuration**: Configure your domains and SSL settings using simple `.conf` files.
> - **Asynchronous Processing**: Utilizes go's async capabilities for efficient handling of multiple connections.
> - **Detailed Logging**: Logs information about each request, including processing time, client IP address, domain, and request path.
> - **Customizable**: Extendable for various use cases and easily integrable into different environments.
> 

## Getting Started

### Configuration

SparkProxy requires domain configuration files to be placed in the `./domains` directory. Each file should have the `.conf` extension and follow this structure:

### Running the Proxy

1. **Set Up Configuration Files:** Create `.conf` files for each domain in the `./domains` directory.
2. **Start SparkProxy:** Execute the main program. By default, it listens on ports 80 (HTTP) and 443 (HTTPS).
3. **Monitor Activity:** Observe the console output for logs detailing requests and server activity.

### Example Configuration File

example.conf
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

### Streams Configuration File

stream.conf
```plaintext
server: {
    domain: smtp.example.com
    location: 192.168.1.60:25
    protocol: tcp
}
```

### Dashboard

SparkProxy includes a user-friendly dashboard for easy monitoring and management. Here's a glimpse of what the dashboard looks like:

<p align="center">
    <img src="./images/analytics.png">
    <img src="./images/auth.png">
    <img src="./images/sites.png">
</p>

### Contributing
Feel free to open issues or submit pull requests if you have ideas or encounter issues. Contributions are always welcome!

### License
SparkProxy is open-source software, and its license information can be found in the LICENSE file in the repository.
