use std::io;

#[derive(Debug)]
pub enum ProxyError {
    Io(io::Error),
    SocksInvalidVersion(u8),
    SocksMethodNotSupported,
    SocksInvalidCommand(u8),
    SocksInvalidAddressType(u8),
    DnsResolutionFailed(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "I/O error: {}", e),
            ProxyError::SocksInvalidVersion(v) => write!(f, "不支持的SOCKS版本：{}", v),
            ProxyError::SocksMethodNotSupported => write!(f, "客户端不支持免密认证"),
            ProxyError::SocksInvalidCommand(c) => write!(f, "不支持的命令类型：{:#04x}", c),
            ProxyError::SocksInvalidAddressType(a) => write!(f, "不支持的地址类型：{:#04x}", a),
            ProxyError::DnsResolutionFailed(domain) => write!(f, "DNS解析失败：{}", domain),
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

impl From<io::Error> for ProxyError {
    fn from(e: io::Error) -> Self {
        ProxyError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;
