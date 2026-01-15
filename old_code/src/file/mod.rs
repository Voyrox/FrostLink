use std::sync::Arc;
use tokio::sync::Mutex;
use std::fs;
use std::vec::Vec;

#[derive(Clone)]
pub struct Config {
    pub domain: String,
    pub location: String,
    pub allow_ssl: bool,
    pub allow_http: bool,
    pub ssl_certificate: Option<String>,
    pub ssl_certificate_key: Option<String>,
}

pub type SharedConfig = Arc<Mutex<Vec<Config>>>;

pub fn parse_config(file_content: &str) -> Result<(String, String, bool, bool, Option<String>, Option<String>), &'static str> {
    let mut domain = None;
    let mut location = None;
    let mut allow_ssl = None;
    let mut allow_http = None;
    let mut ssl_certificate = None;
    let mut ssl_certificate_key = None;

    for line in file_content.lines() {
        if let Some(domain_value) = line.trim().strip_prefix("domain: ") {
            domain = Some(domain_value.to_string());
        } else if let Some(location_value) = line.trim().strip_prefix("location: ") {
            location = Some(location_value.to_string());
        } else if let Some(ssl_value) = line.trim().strip_prefix("AllowSSL: ") {
            allow_ssl = Some(ssl_value.parse().map_err(|_| "Invalid value for AllowSSL")?);
        } else if let Some(http_value) = line.trim().strip_prefix("AllowHTTP: ") {
            allow_http = Some(http_value.parse().map_err(|_| "Invalid value for AllowHTTP")?);
        } else if let Some(cert) = line.trim().strip_prefix("ssl_certificate: ") {
            ssl_certificate = Some(cert.to_string());
        } else if let Some(key) = line.trim().strip_prefix("ssl_certificate_key: ") {
            ssl_certificate_key = Some(key.to_string());
        }
    }

    match (domain, location, allow_ssl, allow_http) {
        (Some(domain), Some(location), ssl, http) => {
            let allow_ssl = ssl.unwrap_or(false);
            let allow_http = http.unwrap_or(true);

            if allow_ssl && (ssl_certificate.is_none() || ssl_certificate_key.is_none()) {
                Err("Missing SSL certificate information for a domain with AllowSSL enabled")
            } else {
                Ok((domain, location, allow_ssl, allow_http, ssl_certificate, ssl_certificate_key))
            }
        },
        _ => Err("Missing required domain or location information"),
    }
}


pub fn read_configs() -> Vec<Config> {
    println!("Reading configuration files...");

    let mut configs = Vec::new();
    match fs::read_dir("./domains") {
        Ok(entries) => {
            let mut found = false;

            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("conf") {
                        found = true;
                        match fs::read_to_string(&path) {
                            Ok(content) => {
                                match parse_config(&content) {
                                    Ok(config_tuple) => {
                                        let config = Config {
                                            domain: config_tuple.0,
                                            location: config_tuple.1,
                                            allow_ssl: config_tuple.2,
                                            allow_http: config_tuple.3,
                                            ssl_certificate: config_tuple.4,
                                            ssl_certificate_key: config_tuple.5,
                                        };
                                        configs.push(config);
                                    },
                                    Err(e) => println!("Error parsing configuration: {}", e),
                                }
                            },
                            Err(e) => println!("Error reading file {:?}: {}", path, e),
                        }
                    }
                }
            }

            if !found {
                println!("No configuration files found in ./domains");
            }
        },
        Err(e) => println!("Error reading ./domains directory: {}", e),
    }
    configs
}

pub async fn update_configs(shared_configs: SharedConfig) {
    let configs = read_configs();
    let mut configs_lock = shared_configs.lock().await;
    *configs_lock = configs;
}
