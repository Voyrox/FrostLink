use std::io::Result;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;
use std::env;
use crate::dashboard::SESSIONS;
use crate::file::SharedConfig;
use crate::statistics::SharedProxyStatistics;

async fn extract_json(buffer: &[u8]) -> Value {
    let buffer_string = std::str::from_utf8(buffer).unwrap_or("");
    let content_length = buffer_string
        .lines()
        .find(|line| line.starts_with("Content-Length:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|num| num.parse::<usize>().ok())
        .unwrap_or(0);

    let json_start_index = buffer_string.find("\r\n\r\n").unwrap_or(0) + 4;
    let json_body = &buffer_string[json_start_index..json_start_index + content_length];
    match serde_json::from_str(json_body) {
        Ok(val) => val,
        Err(e) => {
            println!("Error parsing JSON: {}", e);
            serde_json::json!({})
        }
    }
}

fn construct_json_response(data: HashMap<&str, Value>) -> String {
    let json_body = serde_json::to_string(&data).unwrap_or_else(|_| "{}".to_string());
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}", json_body)
}

pub async fn handle_api_request(configs: SharedConfig, proxy_stats: SharedProxyStatistics, path: &str, buffer: &[u8]) -> Result<String> {
    match path {
        "/api/login" => {
            let json = extract_json(buffer).await;

            let username = json.get("username").and_then(|u| u.as_str()).unwrap_or("");
            let password = json.get("password").and_then(|p| p.as_str()).unwrap_or("");

            let valid_username = env::var("USER").unwrap_or_default();
            let valid_password = env::var("PASSWORD").unwrap_or_default();

            let valid = username == valid_username && password == valid_password;

            if valid {
                let session_id = Uuid::new_v4().to_string();
                let mut sessions = SESSIONS.lock().await;
                sessions.insert(session_id.clone(), username.to_string());
            
                let mut data = HashMap::new();
                data.insert("valid", Value::Bool(true));
                data.insert("session_id", Value::String(session_id));
                Ok(construct_json_response(data))
                
            } else {
                let mut data = HashMap::new();
                data.insert("valid", Value::Bool(false));
                Ok(construct_json_response(data))
            }
        },
        "/api/proxys" => {
            let locked_configs = configs.lock().await;
            let stats = proxy_stats.lock().await;
            let proxies = &*stats.proxies.lock().await;
            
            let configs_json: Vec<_> = locked_configs.iter().map(|config| {
                let mut config_map = serde_json::Map::new();
                
                config_map.insert("domain".to_string(), serde_json::Value::String(config.domain.clone()));
                config_map.insert("host".to_string(), serde_json::Value::String(config.location.clone()));
                config_map.insert("SSL".to_string(), serde_json::Value::Bool(config.allow_ssl));
                config_map.insert("HTTP".to_string(), serde_json::Value::Bool(config.allow_http));
                config_map.insert("pubkey".to_string(), config.ssl_certificate.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null));
                config_map.insert("privkey".to_string(), config.ssl_certificate_key.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null));
                
                if let Some(proxy_stats) = proxies.get(&config.domain) {
                    config_map.insert("total_connections".to_string(), serde_json::Value::Number(serde_json::Number::from(proxy_stats.total_connections)));
                    config_map.insert("last_active".to_string(), serde_json::Value::String(proxy_stats.last_active.clone()));
                    config_map.insert("total_request".to_string(), serde_json::Value::Number(serde_json::Number::from(proxy_stats.total_request)));
                    config_map.insert("total_response".to_string(), serde_json::Value::Number(serde_json::Number::from(proxy_stats.total_response)));
                    config_map.insert("log".to_string(), serde_json::Value::Array(proxy_stats.log.iter().map(|log| {
                        serde_json::json!({
                            "domain": log.domain,
                            "ip": log.ip.to_string(),
                            "path": log.path.clone().unwrap_or_default(),
                            "event": log.event,
                            "time": log.time,
                        })
                    }).collect()));
                } else {
                    config_map.insert("total_connections".to_string(), serde_json::Value::Number(serde_json::Number::from(0)));
                    config_map.insert("total_request".to_string(), serde_json::Value::Number(serde_json::Number::from(0)));
                    config_map.insert("total_response".to_string(), serde_json::Value::Number(serde_json::Number::from(0)));
                }

                serde_json::Value::Object(config_map)
            }).collect();
        
            let mut data = HashMap::new();
            data.insert("configs", serde_json::Value::Array(configs_json));    
            
            Ok(construct_json_response(data))
        },
        "/api/system/stats" => {
            let stats = proxy_stats.lock().await;
            let proxies = &*stats.proxies.lock().await;
        
            let mut proxy_stats_json = serde_json::Map::new();
            for (domain, stats) in proxies.iter() {
                proxy_stats_json.insert(domain.clone(), serde_json::json!({
                    "total_connections": stats.total_connections,
                }));
            }
        
            let system_stats = &stats.system;
            let ddos_stats = &stats.ddos_attacks;
            let data_usage = &stats.data_usage;
        
            let mut data = HashMap::new();
            data.insert("system", serde_json::json!({
                "firewall": {
                    "blocked": system_stats.firewall.blocked,
                    "whitelisted": system_stats.firewall.whitelisted,
                    "blacklisted": system_stats.firewall.blacklisted,
                }
            }));
            data.insert("ddos_attacks", serde_json::json!({
                "blocked": ddos_stats.blocked,
            }));
            data.insert("data_usage", serde_json::json!({
                "upload": data_usage.upload,
                "download": data_usage.download,
            }));
            data.insert("proxies", serde_json::Value::Object(proxy_stats_json));
            
            Ok(construct_json_response(data))
        },
        _ => Ok("HTTP/1.1 404 NOT FOUND\r\n\r\n".to_string())     
    }
}