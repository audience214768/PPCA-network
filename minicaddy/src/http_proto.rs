use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{ProxyError, Result};

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_ROOT: &str = "./www";

pub fn get_header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
}

pub fn wants_keep_alive(headers: &[httparse::Header<'_>]) -> bool {
    get_header(headers, "Connection")
        .map(|v| !v.eq_ignore_ascii_case("close"))
        .unwrap_or(true)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn check_auth(headers: &[httparse::Header<'_>], expected: &str) -> bool {
    let encoded = match get_header(headers, "Authorization").and_then(|v| v.strip_prefix("Basic ")) {
        Some(v) => v,
        None => return false,
    };
    let decoded = match BASE64_STANDARD.decode(encoded) {
        Ok(v) => v,
        Err(_) => return false,
    };
    ct_eq(&decoded, expected.as_bytes())
}

pub fn format_http_date(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as libc::time_t;

    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&secs, &mut tm);
        format!(
            "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
            DAYS[tm.tm_wday as usize],
            tm.tm_mday,
            MONTHS[tm.tm_mon as usize],
            tm.tm_year + 1900,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
        )
    }
}

pub fn etag_for(mtime: SystemTime, size: u64) -> String {
    let ms = mtime.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    format!(r##"W/"{:x}-{:x}""##, ms, size)
}

pub fn parse_range(val: &str, file_size: u64) -> Option<(u64, u64)> {
    let val = val.strip_prefix("bytes=")?;
    let (start_str, end_str) = val.split_once('-')?;

    if start_str.trim().is_empty() {
        let n: u64 = end_str.trim().parse().ok()?;
        return if n == 0 || file_size == 0 { None } else { Some((file_size - n, file_size - 1)) };
    }

    let start: u64 = start_str.trim().parse().ok()?;
    if file_size == 0 || start >= file_size {
        return None;
    }
    let end = if end_str.trim().is_empty() {
        file_size - 1
    } else {
        end_str.trim().parse::<u64>().ok()?.min(file_size - 1)
    };
    (start <= end).then_some((start, end))
}

pub fn mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css")   => "text/css",
        Some("js")    => "application/javascript",
        Some("json")  => "application/json",
        Some("png")   => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif")   => "image/gif",
        Some("svg")   => "image/svg+xml",
        Some("pdf")   => "application/pdf",
        Some("ico")   => "image/x-icon",
        Some("wasm")  => "application/wasm",
        _             => "application/octet-stream",
    }
}

pub fn safe_path(root: &Path, path: &str) -> Option<PathBuf> {
    let target = root.join(path.trim_start_matches('/'));
    if let Ok(canon) = target.canonicalize() {
        if let Ok(root_canon) = root.canonicalize() {
            if canon.starts_with(&root_canon) {
                return Some(canon);
            }
        }
    }
    None
}

pub fn dir_listing_html(dir_path: &Path, request_path: &str) -> String {
    let base = request_path.trim_end_matches('/');
    let mut html = format!(
        "<!DOCTYPE html>\n<html><head><title>Index of {0}</title></head>\n<body>\n\
         <h1>Index of {0}</h1>\n<hr>\n<pre>\n",
        request_path
    );
    if let Ok(entries) = std::fs::read_dir(dir_path) {
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    format!("<a href=\"{base}/{name}/\">{name}/</a>")
                } else {
                    format!("<a href=\"{base}/{name}\">{name}</a>")
                }
            })
            .collect();
        names.sort();
        for n in names {
            html.push_str(&n);
            html.push('\n');
        }
    }
    html.push_str("</pre>\n<hr>\n</body>\n</html>");
    html
}

pub async fn read_chunked_body(stream: &mut TcpStream, prefix: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = prefix.to_vec();
    let mut body = Vec::new();

    loop {
        while !buf.windows(2).any(|w| w == b"\r\n") {
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(ProxyError::HttpInvalidRequest("chunked body truncated".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap();
        let hex = std::str::from_utf8(&buf[..line_end])
            .map_err(|_| ProxyError::HttpInvalidRequest("non-utf8 chunk size".into()))?;
        let size = usize::from_str_radix(hex.split(';').next().unwrap().trim(), 16)
            .map_err(|_| ProxyError::HttpInvalidRequest(format!("bad chunk size: {hex}")))?;
        buf.drain(..line_end + 2);

        if size == 0 {
            if buf.starts_with(b"\r\n") {
                return Ok((body, buf[2..].to_vec()));
            }
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut tmp = [0u8; 4096];
                let n = stream.read(&mut tmp).await?;
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
            }
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok((body, buf[pos + 4..].to_vec()));
            }
            return Ok((body, Vec::new()));
        }

        while buf.len() < size + 2 {
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(ProxyError::HttpInvalidRequest("chunked body truncated".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        body.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

pub async fn read_body(
    stream: &mut TcpStream,
    prefix: &[u8],
    headers: &[httparse::Header<'_>],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if get_header(headers, "Transfer-Encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        return read_chunked_body(stream, prefix).await;
    }

    let content_length = get_header(headers, "Content-Length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    if content_length == 0 {
        return Ok((Vec::new(), prefix.to_vec()));
    }

    let mut buf = prefix.to_vec();
    while buf.len() < content_length {
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ProxyError::HttpInvalidRequest("body truncated".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[..content_length].to_vec();
    let leftover = buf[content_length..].to_vec();
    Ok((body, leftover))
}

pub fn is_compressible(ct: &str) -> bool {
    ct.starts_with("text/") || ct.contains("javascript") || ct.contains("json")
        || ct.contains("xml") || ct.contains("svg")
}

pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).map_err(ProxyError::Io)?;
    e.finish().map_err(ProxyError::Io)
}

pub async fn write_chunk(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(format!("{:x}\r\n", data.len()).as_bytes()).await?;
    stream.write_all(data).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}

pub async fn write_last_chunk(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(b"0\r\n\r\n").await?;
    Ok(())
}

pub async fn write_429(stream: &mut TcpStream) -> Result<()> {
    let body = "429 Too Many Requests";
    let resp = format!(
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\n\
         Content-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

pub async fn write_401(stream: &mut TcpStream) -> Result<()> {
    let body = "401 Unauthorized";
    let resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Restricted\"\r\n\
         Content-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

pub async fn write_502(stream: &mut TcpStream, reason: &str) -> Result<()> {
    let body = format!("502 Bad Gateway\nUpstream: {reason}");
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}


const HOP_BY_HOP: &[&str] = &[
    "connection", "keep-alive", "transfer-encoding",
    "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization",
];

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name))
}

pub fn copy_headers(dst: &mut String, headers: &[httparse::Header<'_>]) {
    for h in headers {
        if is_hop_by_hop(h.name) {
            continue;
        }
        dst.push_str(h.name);
        dst.push_str(": ");
        dst.push_str(std::str::from_utf8(h.value).unwrap_or(""));
        dst.push_str("\r\n");
    }
}
