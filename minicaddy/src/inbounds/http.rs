//! HTTP server — dispatch, keep-alive loop, entry point.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::SiteConfig;
use crate::error::{ProxyError, Result};
use crate::http_proto::*;
use crate::rate_limiter::TokenBucket;
use super::http_files::file_server;
use super::http_proxy::reverse_proxy;

async fn handle_request(
    stream: &mut TcpStream,
    req: &httparse::Request<'_, '_>,
    body_prefix: &[u8],
    sites: &[SiteConfig],
    client_addr: SocketAddr,
    keep_alive: bool,
    rate_limiter: Option<&Mutex<TokenBucket>>,
) -> Result<Vec<u8>> {
    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");

    let (body, leftover) = read_body(stream, body_prefix, req.headers).await?;

    if let Some(limiter) = rate_limiter {
        if !TokenBucket::try_consume(limiter) {
            write_429(stream).await?;
            return Ok(leftover);
        }
    }

    let host = get_header(req.headers, "Host").unwrap_or("localhost");
    let site = sites
        .iter()
        .find(|s| s.host.as_deref() == Some(host))
        .or_else(|| sites.iter().find(|s| s.host.is_none()))
        .expect("no site config for listener");

    if let Some((expected, _realm)) = &site.basic_auth {
        if !check_auth(req.headers, expected) {
            write_401(stream).await?;
            return Ok(leftover);
        }
    }

    if let Some(upstream) = &site.reverse_proxy {
        println!("→ reverse_proxy [{host}]");
        reverse_proxy(stream, method, path, req.headers, &body, upstream, client_addr).await?;
    } else if site.file_server {
        let root = site.root.as_deref().unwrap_or(DEFAULT_ROOT);
        println!("→ file_server [{host}] root={root}");
        file_server(stream, method, path, req.headers, keep_alive, root, site.gzip).await?;
    } else {
        let body = "404 Not Found";
        let resp = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await?;
    }

    Ok(leftover)
}

async fn serve_connection(
    mut stream: TcpStream,
    sites: Arc<Vec<SiteConfig>>,
    rate_limiter: Option<Arc<Mutex<TokenBucket>>>,
) -> Result<()> {
    let addr = stream.peer_addr()?;
    let limiter_ref = rate_limiter.as_deref();
    let mut buffer = Vec::<u8>::new();

    loop {
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&buffer) {
            Ok(httparse::Status::Complete(header_size)) => {
                let keep_alive = wants_keep_alive(req.headers);
                buffer = handle_request(
                    &mut stream, 
                    &req, 
                    &buffer[header_size..],
                    &sites, 
                    addr, 
                    keep_alive, 
                    limiter_ref,
                ).await?;
                if !keep_alive {
                    println!("[{addr}] close");
                    return Ok(());
                }
                continue;
            }
            Err(e) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                return Err(ProxyError::from(e));
            }
            Ok(httparse::Status::Partial) => {}
        }

        let mut tmp = [0u8; 4096];
        let n = match timeout(IDLE_TIMEOUT, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => {
                if buffer.is_empty() {
                    return Ok(());
                }
                return Err(ProxyError::HttpInvalidRequest("incomplete request".into()));
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                println!("[{addr}] idle timeout");
                return Ok(());
            }
        };
        buffer.extend_from_slice(&tmp[..n]);
    }
}

async fn run_http(
    bind_addr: SocketAddr,
    sites: Vec<SiteConfig>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("listening on {bind_addr}");

    let rate_limiter: Option<Arc<Mutex<TokenBucket>>> = sites
        .iter()
        .find_map(|s| s.rate_limit)
        .map(|(rate, burst)| Arc::new(Mutex::new(TokenBucket::new(rate, burst))));

    let sites = Arc::new(sites);

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("[{addr}] connected");
        let sites = sites.clone();
        let limiter = rate_limiter.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, sites, limiter).await {
                println!("[{addr}] error: {e:?}");
            }
        });
    }
}

/// Group sites by listen_addr, then spawn one listener per unique port.
pub async fn run_all(sites: &[SiteConfig]) -> Result<()> {
    let mut by_port: HashMap<String, Vec<SiteConfig>> = HashMap::new();
    for site in sites {
        by_port
            .entry(site.listen_addr.clone())
            .or_default()
            .push(site.clone());
    }

    let mut handles = Vec::new();
    for (addr, sites) in by_port {
        let addr: SocketAddr = addr
            .parse()
            .unwrap_or_else(|e| panic!("invalid listen address '{addr}': {e}"));
        handles.push(tokio::spawn(run_http(addr, sites)));
    }

    for h in handles {
        h.await.unwrap()?;
    }

    Ok(())
}
