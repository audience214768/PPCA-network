mod config;
mod error;
mod socks5_proto;
mod relay;
mod inbounds;

use config::Config;
use error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env();

    if let Some(socks5_addr) = config.socks5_addr {
        let udp_idle_timeout = config.udp_idle_timeout;
        tokio::spawn(async move {
            if let Err(e) = inbounds::run_socks5_tcp(socks5_addr, udp_idle_timeout).await {
                println!("SOCKS5 监听器异常退出：{:?}", e);
            }
        });
    }

    if let Some(tproxy_addr) = config.tproxy_addr {
        println!("TPROXY 功能已启用：{}", tproxy_addr);
        tokio::spawn(async move {
            if let Err(e) = inbounds::run_tproxy_tcp(tproxy_addr).await {
                println!("TPROXY 监听器异常退出：{:?}", e);
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");
    Ok(())
}
