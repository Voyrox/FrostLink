use crate::file::SharedConfig;
use crate::statistics::SharedProxyStatistics;
use crate::BColors;
use std::fs::read_to_string;
use std::time::Instant;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::global;

pub async fn handle_client(
    configs: SharedConfig,
    proxy_stats: SharedProxyStatistics,
    colors: BColors,
    mut client_stream: TcpStream,
) -> io::Result<()> {
    let start_time = Instant::now();

    let mut buffer = vec![0; 1024];
    let request_size = client_stream.read(&mut buffer).await?;

    let request_str = String::from_utf8_lossy(&buffer[0..request_size]);

    let configs_lock = configs.lock().await;

    if !configs_lock.iter().any(|config| config.allow_http) {
        eprintln!(
            "{}[ARCTICARCH]{} HTTP requests are not allowed",
            colors.fail, colors.endc
        );
        return Ok(());
    }

    let domain_and_location = configs_lock
        .iter()
        .find(|config| request_str.contains(&format!("Host: {}", config.domain)))
        .cloned();

    if let Some(config) = domain_and_location {
        {
            let stats = proxy_stats.lock().await;
            let proxies = &mut *stats.proxies.lock().await;
            let domain_stats = proxies.entry(config.domain.clone()).or_default();
            let ip = client_stream.peer_addr().unwrap().ip();
            let path = request_str.lines().find_map(|line| {
                if line.starts_with("GET") || line.starts_with("POST") {
                    line.split_whitespace().nth(1)
                } else {
                    None
                }
            }).unwrap_or_default();

            global::globallog::logger(&config.domain, ip, Some(path.to_string()), "HTTP", domain_stats, start_time);
            global::request_size(true, domain_stats, request_size as u64);
            domain_stats.total_connections += 1;
        }
        if let Ok(mut local_stream) = TcpStream::connect(&config.location).await {
            if local_stream.write_all(&buffer[0..request_size]).await.is_ok() {
                let response_size = match io::copy(&mut local_stream, &mut client_stream).await {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        eprintln!(
                            "{}[ARCTICARCH]{} Failed to send response to client",
                            colors.fail, colors.endc
                        );
                        return Ok(());
                    },
                };

                {
                    let stats = proxy_stats.lock().await;
                    let proxies = &mut *stats.proxies.lock().await;
                    let domain_stats = proxies.get_mut(&config.domain).unwrap();
                    global::request_size(false, domain_stats, response_size as u64);
                }

                let elapsed_time = start_time.elapsed();
                println!(
                    "Time taken: {:?} : {} : {} : SSL: False",
                    elapsed_time,
                    client_stream.peer_addr().unwrap().ip(),
                    config.domain
                );
            } else {
                eprintln!(
                    "{}[ARCTICARCH]{} Failed to send request to {}",
                    colors.fail, colors.endc, config.location
                );
            }
        } else {
            eprintln!(
                "{}[ARCTICARCH]{} Could not connect to {}",
                colors.fail, colors.endc, config.location
            );
        }
    } else {
        let response = read_to_string("./default/index.html")
            .map(|contents| format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{}", contents))
            .unwrap_or_else(|_| "HTTP/1.1 404 NOT FOUND\r\nContent-Type: text/html\r\n\r\n<html><head><title>Not Found</title></head><body><h1>404 - File Not Found</h1></body></html>".to_string());

        let response_bytes = response.as_bytes();
        client_stream.write_all(response_bytes).await?;
    }

    Ok(())
}