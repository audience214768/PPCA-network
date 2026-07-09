//! Static file server handler.

use std::io::SeekFrom;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, copy};
use tokio::net::TcpStream;

use crate::error::Result;
use crate::http_proto::*;

pub async fn file_server(
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    req_headers: &[httparse::Header<'_>],
    keep_alive: bool,
    root: &str,
    enable_gzip: bool,
) -> Result<()> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let is_head = method.eq_ignore_ascii_case("HEAD");
    let wants_gzip = enable_gzip
        && get_header(req_headers, "Accept-Encoding")
            .map(|v| v.contains("gzip"))
            .unwrap_or(false);

    let target = match safe_path(Path::new(root), path) {
        Some(p) => p,
        None => {
            let resp = format!("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: {conn}\r\n\r\nNot Found");
            stream.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    };

    if target.is_dir() {
        let html = dir_listing_html(&target, path);
        if wants_gzip {
            let data = compress(html.as_bytes())?;
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\
                 Vary: Accept-Encoding\r\nConnection: {conn}\r\n\r\n"
            );
            stream.write_all(hdr.as_bytes()).await?;
            if !is_head {
                write_chunk(stream, &data).await?;
                write_last_chunk(stream).await?;
            }
        } else {
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: {conn}\r\n\r\n",
                html.len()
            );
            stream.write_all(hdr.as_bytes()).await?;
            if !is_head {
                stream.write_all(html.as_bytes()).await?;
            }
        }
        return Ok(());
    }

    let mut file = tokio::fs::File::open(&target).await?;
    let meta = file.metadata().await?;
    let file_size = meta.len();
    let mtime = meta.modified()?;
    let etag = etag_for(mtime, file_size);
    let last_mod = format_http_date(mtime);
    let ct = mime_type(&target);

    if let Some(client_etag) = get_header(req_headers, "If-None-Match") {
        if client_etag == etag {
            let resp = format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nConnection: {conn}\r\n\r\n");
            stream.write_all(resp.as_bytes()).await?;
            println!("→ 304 ({path})");
            return Ok(());
        }
    }

    if let Some(range_val) = get_header(req_headers, "Range") {
        if let Some((start, end)) = parse_range(range_val, file_size) {
            let len = end - start + 1;
            file.seek(SeekFrom::Start(start)).await?;
            let hdr = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{file_size}\r\n\
                 Content-Length: {len}\r\nContent-Type: {ct}\r\nETag: {etag}\r\nConnection: {conn}\r\n\r\n"
            );
            stream.write_all(hdr.as_bytes()).await?;
            if !is_head {
                copy(&mut file.take(len), stream).await?;
            }
            println!("→ 206 ({path}) bytes {start}-{end}");
            return Ok(());
        }
        let resp = format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{file_size}\r\nConnection: {conn}\r\n\r\n"
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if wants_gzip && is_compressible(ct) && !is_head {
        let mut data = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut data).await?;
        let compressed = compress(&data)?;
        let hdr = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n\
             Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\
             Vary: Accept-Encoding\r\nConnection: {conn}\r\n\r\n"
        );
        stream.write_all(hdr.as_bytes()).await?;
        write_chunk(stream, &compressed).await?;
        write_last_chunk(stream).await?;
        println!("→ 200 gzip ({path}) {file_size} → {} bytes", compressed.len());
    } else {
        let hdr = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {file_size}\r\nContent-Type: {ct}\r\n\
             ETag: {etag}\r\nLast-Modified: {last_mod}\r\nConnection: {conn}\r\n\r\n"
        );
        stream.write_all(hdr.as_bytes()).await?;
        if !is_head {
            copy(&mut file, stream).await?;
        }
        println!("→ 200 ({path})");
    }
    Ok(())
}
