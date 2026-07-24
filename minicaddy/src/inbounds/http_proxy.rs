//! Reverse proxy handler.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use tokio::net::TcpStream;

use crate::error::Result;
use crate::http_proto::*;

pub async fn reverse_proxy(
    client: &mut TcpStream,
    method: &str,
    path: &str,
    headers: &[httparse::Header<'_>],
    body: &[u8],
    upstream_addr: &str,
    client_addr: SocketAddr,
) -> Result<()> {
    let upstream_path = path.strip_prefix("/api").unwrap_or(path);
    let upstream_path = if upstream_path.is_empty() { "/" } else { upstream_path };

    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(u) => u,
        Err(e) => {
            println!("upstream connect failed {upstream_addr}: {e}");
            return write_502(client, &e.to_string()).await;
        }
    };
    println!("proxy → {method} {upstream_addr}{upstream_path}");

    let mut req = format!("{method} {upstream_path} HTTP/1.1\r\n");
    copy_headers(&mut req, headers);
    req.push_str(&format!("X-Forwarded-For: {}\r\n", client_addr.ip()));
    req.push_str("X-Forwarded-Proto: http\r\n\r\n");
    upstream.write_all(req.as_bytes()).await?;
    if !body.is_empty() {
        upstream.write_all(body).await?;
    }

    let mut buf = [0u8; 4096];
    let n = upstream.read(&mut buf).await?;
    if n == 0 {
        return write_502(client, "upstream closed connection").await;
    }

    let mut resp_headers = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Response::new(&mut resp_headers);
    let header_size = match resp.parse(&buf[..n]) {
        Ok(httparse::Status::Complete(s)) => s,
        Ok(httparse::Status::Partial) => return write_502(client, "incomplete response").await,
        Err(_) => return write_502(client, "bad response").await,
    };
    println!("upstream → {}", resp.code.unwrap_or(502));

    client.write_all(&buf[..header_size]).await?;
    if header_size < n {
        client.write_all(&buf[header_size..n]).await?;
    }
    copy(&mut upstream, client).await?;
    Ok(())
}
