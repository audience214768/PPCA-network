//! Site configuration and Caddyfile parser.

use crate::error::{ProxyError, Result};

/// One Caddyfile block → one site (listener or virtual host).
#[derive(Debug, Clone)]
pub struct SiteConfig {
    pub listen_addr: String,              // "0.0.0.0:8080"
    pub host: Option<String>,             // virtual-host matching (None = catch-all)
    pub root: Option<String>,             // "root" directive
    pub file_server: bool,                // "file_server" directive
    pub gzip: bool,                       // "gzip" directive
    pub log: bool,                        // "log" directive
    pub reverse_proxy: Option<String>,    // "reverse_proxy" directive
    pub basic_auth: Option<(String, String)>, // ("user:pwd", "realm")
    pub rate_limit: Option<(f64, f64)>,   // (rate, burst)
}

pub struct Config {
    pub sites: Vec<SiteConfig>,
}

impl Config {
    pub fn from_caddyfile(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Io(e))?;

        let mut sites = Vec::new();

        for block in content.split('}') {
            let block = block.trim();
            if block.is_empty() {
                continue;
            }

            let (addr_part, body) = match block.split_once('{') {
                Some(p) => p,
                None => continue,
            };

            let addr_part = addr_part.trim();
            let addr = addr_part
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .last()
                .unwrap_or("")
                .trim();
            if addr.is_empty() {
                continue;
            }
            let body = body.trim();

            let (host, port) = if let Some((h, p)) = addr.rsplit_once(':') {
                if h.is_empty() {
                    (None, p.to_string())
                } else {
                    (Some(h.to_string()), p.to_string())
                }
            } else {
                (Some(addr.to_string()), "80".to_string())
            };

            let listen_addr = format!("0.0.0.0:{port}");

            let mut site = SiteConfig {
                listen_addr,
                host,
                root: None,
                file_server: false,
                gzip: false,
                log: false,
                reverse_proxy: None,
                basic_auth: None,
                rate_limit: None,
            };

            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let directive = match parts.next() {
                    Some(d) => d,
                    None => continue,
                };

                match directive {
                    "root" => {
                        site.root = parts.next().map(String::from);
                        site.file_server = true; // root implies file_server
                    }
                    "file_server" => site.file_server = true,
                    "gzip" => site.gzip = true,
                    "log" => site.log = true,
                    "reverse_proxy" => {
                        site.reverse_proxy = parts.next().map(String::from);
                    }
                    "rate_limit" => {
                        let r: f64 = parts
                            .next()
                            .expect("rate_limit: missing rate")
                            .parse()
                            .expect("rate_limit: invalid rate");
                        let b: f64 = parts
                            .next()
                            .expect("rate_limit: missing burst")
                            .parse()
                            .expect("rate_limit: invalid burst");
                        site.rate_limit = Some((r, b));
                    }
                    "basic_auth" => {
                        let u = parts.next();
                        let p = parts.next();
                        let realm = parts.next();
                        if let (Some(u), Some(p), Some(r)) = (u, p, realm) {
                            let realm = r.trim_matches('"');
                            site.basic_auth =
                                Some((format!("{u}:{p}"), realm.to_string()));
                        }
                    }
                    _ => eprintln!("unknown directive: {directive}"),
                }
            }

            sites.push(site);
        }

        Ok(Config { sites })
    }
}
