use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "TCP-stack", about = "Userspace TCP/IP stack over TAP device")]
pub struct Config {
    /// TAP device name (e.g. tap0)
    pub tap_name: String,

    /// Our IP address on the TAP network
    #[arg(long, default_value = "10.0.0.2")]
    pub ip: String,

    /// Connect to remote as client (format: IP:PORT)
    #[arg(long, value_name = "IP:PORT")]
    pub connect: Option<String>,

    /// Data to send (for client mode, e.g. HTTP request)
    #[arg(long)]
    pub data: Option<String>,
}

impl Config {
    pub fn our_ip(&self) -> [u8; 4] {
        parse_ip(&self.ip)
    }
}

pub(crate) fn parse_ip(s: &str) -> [u8; 4] {
    let parts: Vec<u8> = s.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    let mut ip = [0u8; 4];
    for (i, &b) in parts.iter().take(4).enumerate() {
        ip[i] = b;
    }
    ip
}

/// Parse "IP:PORT" string
pub fn parse_addr(s: &str) -> Option<([u8; 4], u16)> {
    let (ip_str, port_str) = s.rsplit_once(':')?;
    let ip = parse_ip(ip_str);
    let port: u16 = port_str.parse().ok()?;
    Some((ip, port))
}
