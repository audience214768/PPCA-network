use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub socks5_addr: Option<SocketAddr>,
    pub tproxy_addr: Option<SocketAddr>,
    pub udp_idle_timeout: Duration,
}

impl Config {
    pub fn from_env() -> Self {
        let socks5_addr = std::env::var("SOCKS5_ADDR")
            .ok()
            .map(|s| s.parse().expect("invalid SOCKS5_ADDR"));

        let tproxy_addr = std::env::var("TPROXY_ADDR")
            .ok()
            .map(|s| s.parse().expect("invalid TPROXY_ADDR"));

        let udp_idle_timeout = Duration::from_secs(
            std::env::var("UDP_IDLE_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
        );

        Self {
            socks5_addr,
            tproxy_addr,
            udp_idle_timeout,
        }
    }
}
