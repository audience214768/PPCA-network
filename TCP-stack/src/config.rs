use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "TCP-stack", about = "Userspace TCP/IP stack over TAP device")]
pub struct Config {
    /// TAP device name (e.g. tap0)
    pub tap_name: String,

    /// Our IP address on the TAP network
    #[arg(long, default_value = "10.0.0.2")]
    pub ip: String,

    /// Listen on this TCP port
    #[arg(long, value_name = "PORT")]
    pub listen: Option<u16>,
}

impl Config {
    pub fn our_ip(&self) -> [u8; 4] {
        parse_ip(&self.ip)
    }
}

fn parse_ip(s: &str) -> [u8; 4] {
    let parts: Vec<u8> = s.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    let mut ip = [0u8; 4];
    for (i, &b) in parts.iter().take(4).enumerate() {
        ip[i] = b;
    }
    ip
}
