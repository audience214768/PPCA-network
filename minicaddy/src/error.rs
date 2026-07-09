use std::io;

#[derive(Debug)]
pub enum ProxyError {
    Io(io::Error),
    HttpInvalidRequest(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "I/O error: {}", e),
            ProxyError::HttpInvalidRequest(reason) => write!(f, "HTTP 请求无效：{}", reason),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProxyError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<httparse::Error> for ProxyError {
    fn from(e: httparse::Error) -> Self {
        ProxyError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl From<io::Error> for ProxyError {
    fn from(e: io::Error) -> Self {
        ProxyError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;
