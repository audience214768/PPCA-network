mod config;
mod error;
mod http_proto;
mod inbounds;
mod rate_limiter;

use config::Config;
use error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_caddyfile("./Caddyfile")
        .expect("failed to load Caddyfile");

    println!("minicaddy starting with {} site(s)", config.sites.len());
    inbounds::run_all(&config.sites).await
}
