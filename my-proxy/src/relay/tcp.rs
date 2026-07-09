use tokio::net::TcpStream;

use crate::error::Result;

pub async fn relay(client: &mut TcpStream, server: &mut TcpStream) -> Result<()> {
    tokio::io::copy_bidirectional(client, server).await?;
    Ok(())
}
