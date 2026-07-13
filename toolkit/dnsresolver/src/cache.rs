//! Thread-safe DNS cache: positive records, negative (NXDOMAIN) cache,
//! and root-hints loader.

use crate::message::{DnsRR, RData, TYPE_A, TYPE_NS, CLASS_IN};
use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;
use std::time::{Duration, Instant};

type CacheKey = (String, u16, u16); // (name, type, class)

struct CacheEntry {
    rr: DnsRR,
    expires: Instant,
}

pub struct DnsCache {
    records: RwLock<HashMap<CacheKey, Vec<CacheEntry>>>,
    negatives: RwLock<HashMap<CacheKey, Instant>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            negatives: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, name: &str, qtype: u16, qclass: u16) -> Option<Vec<DnsRR>> {
        let key = (name.to_ascii_lowercase(), qtype, qclass);
        let mut records = self.records.write().unwrap();
        if let Some(entries) = records.get_mut(&key) {
            let now = Instant::now();
            entries.retain(|e| e.expires > now);
            if entries.is_empty() {
                records.remove(&key);
                return None;
            }
            Some(entries.iter().map(|e| e.rr.clone()).collect())
        } else {
            None
        }
    }

    pub fn put(&self, rr: &DnsRR) {
        let key = (rr.name.to_ascii_lowercase(), rr.rtype, rr.class);
        let new_expires = Instant::now() + Duration::from_secs(rr.ttl as u64);
        let mut records = self.records.write().unwrap();
        let entries = records.entry(key).or_default();
        for entry in entries.iter_mut() {
            if entry.rr.rdata == rr.rdata {
                entry.expires = new_expires;
                entry.rr.ttl = rr.ttl;
                return;
            }
        }
        entries.push(CacheEntry {
            rr: rr.clone(),
            expires: new_expires,
        });
    }

    pub fn put_all(&self, rrs: &[DnsRR]) {
        for rr in rrs {
            self.put(rr);
        }
    }

    pub fn put_nxdomain(&self, name: &str, qtype: u16, qclass: u16, ttl: u32) {
        let key = (name.to_ascii_lowercase(), qtype, qclass);
        let expires = Instant::now() + Duration::from_secs(ttl as u64);
        self.negatives.write().unwrap().insert(key, expires);
    }

    pub fn is_nxdomain(&self, name: &str, qtype: u16, qclass: u16) -> bool {
        let key = (name.to_ascii_lowercase(), qtype, qclass);
        let neg = self.negatives.read().unwrap();
        if let Some(&expires) = neg.get(&key) {
            if Instant::now() < expires {
                return true;
            }
        }
        false
    }

    pub fn get_ns_ips(&self, zone: &str) -> Vec<(String, std::net::Ipv4Addr)> {
        let zone = zone.to_ascii_lowercase();
        let ns_records = self.get(&zone, TYPE_NS, CLASS_IN).unwrap_or_default();

        let mut result = Vec::new();
        for ns in &ns_records {
            let ns_name = match &ns.rdata {
                RData::NS(name) => name.clone(),
                _ => continue,
            };
            let a_records = self.get(&ns_name, TYPE_A, CLASS_IN).unwrap_or_default();
            for a in &a_records {
                if let RData::A(ip) = a.rdata {
                    result.push((ns_name.clone(), std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])));
                }
            }
        }
        result
    }

    pub fn load_root_hints(&self, path: &str) -> Result<(), String> {
        let content = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            // Format: <name> <ttl> <type> <rdata...>
            let mut idx = 0;
            let name = parts[idx].to_string();
            idx += 1;
            let ttl: u32 = parts[idx].parse().unwrap_or(3600000);
            idx += 1;
            if parts[idx].eq_ignore_ascii_case("IN") || parts[idx].eq_ignore_ascii_case("CLASS1") {
                idx += 1;
            }
            let rtype_str = parts[idx];
            idx += 1;

            let rr = match rtype_str {
                "A" => {
                    let ip_str = parts[idx];
                    let octets: Vec<u8> = ip_str.split('.').filter_map(|s| s.parse().ok()).collect();
                    if octets.len() != 4 {
                        continue;
                    }
                    DnsRR {
                        name,
                        rtype: TYPE_A,
                        class: CLASS_IN,
                        ttl,
                        rdata: RData::A([octets[0], octets[1], octets[2], octets[3]]),
                    }
                }
                "NS" => {
                    let ns_name = parts[idx];
                    DnsRR {
                        name,
                        rtype: TYPE_NS,
                        class: CLASS_IN,
                        ttl,
                        rdata: RData::NS(ns_name.to_string()),
                    }
                }
                _ => continue,
            };
            self.put(&rr);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_cache() {
        let cache = DnsCache::new();
        let rr = DnsRR {
            name: "example.com.".to_string(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl: 3600,
            rdata: RData::A([93, 184, 216, 34]),
        };
        cache.put(&rr);

        let result = cache.get("example.com.", TYPE_A, CLASS_IN);
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0].rdata, RData::A([93, 184, 216, 34]));
    }

    #[test]
    fn test_negative_cache() {
        let cache = DnsCache::new();
        cache.put_nxdomain("noexist.com.", TYPE_A, CLASS_IN, 60);
        assert!(cache.is_nxdomain("noexist.com.", TYPE_A, CLASS_IN));
        assert!(!cache.is_nxdomain("example.com.", TYPE_A, CLASS_IN));
    }

    #[test]
    fn test_root_hints() {
        let cache = DnsCache::new();
        // Manually add a root NS record (mimics root.hints)
        cache.put(&DnsRR {
            name: ".".to_string(),
            rtype: TYPE_NS,
            class: CLASS_IN,
            ttl: 3600000,
            rdata: RData::NS("a.root-servers.net.".to_string()),
        });
        cache.put(&DnsRR {
            name: "a.root-servers.net.".to_string(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl: 3600000,
            rdata: RData::A([198, 41, 0, 4]),
        });

        let ns = cache.get(".", TYPE_NS, CLASS_IN);
        assert!(ns.is_some(), "root NS records should be cached");
        assert!(!ns.unwrap().is_empty());
    }
}
