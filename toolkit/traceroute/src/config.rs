use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "traceroute", about = "Trace the route to a network host")]
pub struct Config {
    /// Maximum TTL (default: 30)
    #[arg(short = 'm', default_value = "30")]
    pub max_hops: u8,

    /// Number of probes per hop (default: 3)
    #[arg(short = 'q', default_value = "3")]
    pub nqueries: u8,

    /// Timeout per hop in seconds (default: 3.0)
    #[arg(short = 'w', default_value = "3.0")]
    pub timeout: f64,

    /// Use ICMP Echo mode instead of UDP (default: UDP)
    #[arg(short = 'I')]
    pub icmp_mode: bool,

    /// Starting TTL (default: 1)
    #[arg(short = 'f', default_value = "1")]
    pub first_ttl: u8,

    /// Target host
    pub host: String,
}
