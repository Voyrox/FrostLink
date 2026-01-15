use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Instant;
use std::fs::{File, read_to_string};
use std::io::BufReader;
use std::path::Path;
use rustls::{
    ServerConfig, NoClientAuth, ResolvesServerCertUsingSNI, 
    internal::pemfile::{certs, pkcs8_private_keys},
    sign::{CertifiedKey, RSASigningKey},
    Certificate, PrivateKey
};
use tokio_rustls::TlsAcceptor;
use crate::BColors;
use crate::components;
use crate::global;
use crate::file::SharedConfig;
use crate::statistics::SharedProxyStatistics;

fn load_cert_and_key(cert_path: &Path, key_path: &Path) -> std::io::Result<(Vec<Certificate>, PrivateKey)> {
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let key_file = &mut BufReader::new(File::open(key_path)?);

    let cert_chain = certs(cert_file)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse certs"))?;
    let mut keys = pkcs8_private_keys(key_file)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse keys"))?;
    Ok((cert_chain, keys.remove(0)))
}

pub async fn handle_client(configs: SharedConfig, proxy_stats: SharedProxyStatistics, colors: BColors, client_stream: TcpStream) -> std::io::Result<()> {
    let start_time = Instant::now();
    let ip = client_stream.peer_addr().unwrap().ip();
    let mut buffer = vec![0; 1024];
    let mut rustls_config = ServerConfig::new(NoClientAuth::new());

    let mut resolver = ResolvesServerCertUsingSNI::new();
    let configs_lock = configs.lock().await;

    for config in configs_lock.iter() {
        let ssl_certificate = config.ssl_certificate.as_deref().unwrap_or_default();
        let ssl_certificate_key = config.ssl_certificate_key.as_deref().unwrap_or_default();

        match load_cert_and_key(Path::new(&ssl_certificate), Path::new(&ssl_certificate_key)) {
            Ok((cert_chain, key)) => {
                let signing_key = RSASigningKey::new(&key)
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to create signing key"))?;
                let certified_key = CertifiedKey::new(cert_chain, Arc::new(Box::new(signing_key)));
    
                if resolver.add(&config.domain, certified_key).is_err() {
                    eprintln!("{}[ARCTICARCH]{} Failed to add certificate for domain {}", colors.fail, colors.endc, &config.domain);
                }
            },
            Err(_) => {
                eprintln!("{}[ARCTICARCH]{} Failed to load certificate and key for domain {}", colors.fail, colors.endc, &config.domain);
                continue;
            }
        }
    }

    rustls_config.cert_resolver = Arc::new(resolver);

    let tls_acceptor = TlsAcceptor::from(Arc::new(rustls_config));
    let mut tls_stream = tls_acceptor.accept(client_stream).await?;

    let size = tls_stream.read(&mut buffer).await?;
    let request_str = String::from_utf8_lossy(&buffer[0..size]);
    let request_path = request_str.split_whitespace().nth(1).unwrap_or("/").to_string();

    let allow_ssl = configs_lock.iter().any(|config| config.allow_ssl);

    if !allow_ssl {
        eprintln!("{}[ARCTICARCH]{} SSL requests are not allowed", colors.fail, colors.endc);
        return Ok(());
    }

    let domain_and_location = {
        let host_header = request_str.lines()
            .find(|line| line.starts_with("Host:"))
            .and_then(|line| line.splitn(2, ':').nth(1))
            .and_then(|host| host.split_whitespace().next())
            .map(|host| host.to_string());
    
        configs_lock.iter().find(|config| {
            host_header.as_ref() == Some(&config.domain)
        }).cloned()
    };    

    if let Some(config) = domain_and_location {
        {
            let stats_lock = proxy_stats.lock().await;
            let mut proxies_lock = stats_lock.proxies.lock().await;
            let domain_stats = proxies_lock.entry(config.domain.clone()).or_default();
            global::request_size(true, domain_stats, size as u64);
            let path = request_str.lines().next().unwrap_or_default().split_whitespace().nth(1).unwrap_or_default();
   
            global::globallog::logger(&config.domain, ip, Some(path.to_string()), "HTTP", domain_stats, start_time);  
            domain_stats.total_connections += 1;
        }
        
        let domain = &config.domain;
        let location = &config.location;

        let ssl_certificate = config.ssl_certificate.as_deref().unwrap_or_default();
        let ssl_certificate_key = config.ssl_certificate_key.as_deref().unwrap_or_default();

        let mut rustls_config = ServerConfig::new(NoClientAuth::new());
        let cert_file = components::load_cert(Path::new(&ssl_certificate))?;
        let key_file = components::load_private_key(Path::new(&ssl_certificate_key))?;
        rustls_config.set_single_cert(cert_file, key_file).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if let Ok(mut remote_stream) = TcpStream::connect(&location).await {
        if remote_stream.write(&buffer[0..size]).await.is_ok() {
            if io::copy(&mut remote_stream, &mut tls_stream).await.is_ok() {
                let ip = tls_stream.get_ref().0.peer_addr().unwrap().ip();
                let elapsed_time = start_time.elapsed();
                let stats = proxy_stats.lock().await;
                let mut proxies = stats.proxies.lock().await;
                let domain_stats = proxies.entry(config.domain.clone()).or_default();
                global::request_size(true, domain_stats, size as u64);
                println!("Time taken: {:?} : {} : {} : {} : SSL: True", elapsed_time, ip, domain, request_path);
            } else {
                eprintln!("{}[ARCTICARCH]{} Failed to send response to client", colors.fail, colors.endc);
            }
            } else {
                eprintln!("{}[ARCTICARCH]{} SSL Failed to send request to {}", colors.fail, colors.endc, location);
            }
        } else {
            eprintln!("{}[ARCTICARCH]{} Could not connect to {}", colors.fail, colors.endc, location);
        }
    } else {
        let default_file_path = "./default/index.html";
        match read_to_string(default_file_path) {
            Ok(contents) => {
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{}", contents);
                tls_stream.write_all(response.as_bytes()).await?;
            }
            Err(_) => {
                let response = "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n<html><head><title>Not Found</title></head><body><h1>404 - File Not Found</h1></body></html>";
                tls_stream.write_all(response.as_bytes()).await?;
                eprintln!("{}[ARCTICARCH]{} Failed to read the default index.html file from {}", colors.fail, colors.endc, default_file_path);
            }
        }
    }

    Ok(())
}
