use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ping", about = "Send ICMP Echo Requests to a network host")]
pub struct Config {
    #[arg(short = 'c')]
    pub count: Option<u32>,

    #[arg(short = 'i', default_value = "1.0")]
    pub interval: f64,

    #[arg(short = 's', default_value = "56")]
    pub size: usize,

    #[arg(short = 't', default_value = "2.0")]
    pub timeout: f64,

    pub host: String,
}
