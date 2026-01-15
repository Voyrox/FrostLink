use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct ProxyStatistics {
    pub system: SystemStats,
    pub ddos_attacks: DDoSStats,
    pub data_usage: DataUsage,
    pub proxies: Arc<Mutex<HashMap<String, ProxyDomainStats>>>,
}

impl Default for ProxyStatistics {
    fn default() -> Self {
        ProxyStatistics {
            system: SystemStats::default(),
            ddos_attacks: DDoSStats::default(),
            data_usage: DataUsage::default(),
            proxies: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub type SharedProxyStatistics = Arc<Mutex<ProxyStatistics>>;

//________________________________________________________________
                        //System 
//________________________________________________________________
#[derive(Clone, Default)]
pub struct SystemStats {
    pub firewall: FirewallStats,
}

#[derive(Clone, Default)]
pub struct FirewallStats {
    pub blocked: usize,
    pub whitelisted: Vec<String>,
    pub blacklisted: Vec<String>,
}

//________________________________________________________________
                        //DDOS Stats 
//________________________________________________________________
#[derive(Clone, Default)]
pub struct DDoSStats {
    pub blocked: usize,
}

//________________________________________________________________
                        //Data Usage 
//________________________________________________________________
#[derive(Clone, Default)]
pub struct DataUsage {
    pub upload: usize,
    pub download: usize,
}

//________________________________________________________________
                        //Proxys
//________________________________________________________________
#[derive(Clone, Default)]
pub struct ProxyDomainStats {
    pub total_connections: usize,
    pub last_active: String,
    pub total_request: usize,
    pub total_response: usize,
    pub log: Vec<LogEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogEntry {
    pub domain: String,
    pub ip: std::net::IpAddr,
    pub path: Option<String>,
    pub event: &'static str,
    pub time: String,
}