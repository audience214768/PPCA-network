//! SOCKS5 protocol (RFC 1928) — address types, handshake, request/reply framing.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{ProxyError, Result};

#[derive(Debug, Clone)]
pub enum Address {
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl Address {
    pub fn from_socks5(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(ProxyError::SocksInvalidAddressType(0xFF));
        }
        let atyp = data[0];
        match atyp {
            0x01 => {
                if data.len() < 7 {
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "地址数据不完整",
                    )));
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((Address::Ipv4(ip, port), 7))
            }
            0x03 => {
                if data.len() < 2 {
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "域名长度字段不完整",
                    )));
                }
                let domain_len = data[1] as usize;
                let end = 2 + domain_len + 2; 
                if data.len() < end {
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "域名数据不完整",
                    )));
                }
                let domain = String::from_utf8(data[2..2 + domain_len].to_vec()).map_err(|_| {
                    ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "域名不是有效的UTF-8编码",
                    ))
                })?;
                let port = u16::from_be_bytes([data[2 + domain_len], data[2 + domain_len + 1]]);
                Ok((Address::Domain(domain, port), end))
            }
            0x04 => {
                if data.len() < 19 {
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "IPv6地址数据不完整",
                    )));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((Address::Ipv6(ip, port), 19))
            }
            _ => Err(ProxyError::SocksInvalidAddressType(atyp)),
        }
    }

    pub fn to_socks5_bytes(&self) -> Vec<u8> {
        match self {
            Address::Ipv4(ip, port) => {
                let mut v = Vec::with_capacity(7);
                v.push(0x01);
                v.extend_from_slice(&ip.octets());
                v.extend_from_slice(&port.to_be_bytes());
                v
            }
            Address::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                let mut v = Vec::with_capacity(4 + domain_bytes.len());
                v.push(0x03);
                v.push(domain_bytes.len() as u8);
                v.extend_from_slice(domain_bytes);
                v.extend_from_slice(&port.to_be_bytes());
                v
            }
            Address::Ipv6(ip, port) => {
                let mut v = Vec::with_capacity(19);
                v.push(0x04);
                v.extend_from_slice(&ip.octets());
                v.extend_from_slice(&port.to_be_bytes());
                v
            }
        }
    }

    pub async fn resolve(&self) -> Result<SocketAddr> {
        match self {
            Address::Ipv4(ip, port) => {
                Ok(SocketAddr::new(std::net::IpAddr::V4(*ip), *port))
            }
            Address::Ipv6(ip, port) => {
                Ok(SocketAddr::new(std::net::IpAddr::V6(*ip), *port))
            }
            Address::Domain(domain, port) => {
                let addr = tokio::net::lookup_host(format!("{}:{}", domain, port))
                    .await?
                    .next()
                    .ok_or_else(|| ProxyError::DnsResolutionFailed(domain.clone()))?;
                Ok(addr)
            }
        }

    }

    pub async fn resolve_ipv4(&self) -> Result<SocketAddr> {
        match self {
            Address::Ipv4(ip, port) => {
                Ok(SocketAddr::new(std::net::IpAddr::V4(*ip), *port))
            }
            Address::Ipv6(_, _) => {
                Err(ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "UDP reply要求IPv4地址，但目标是IPv6",
                )))
            }
            Address::Domain(domain, port) => {
                tokio::net::lookup_host(format!("{}:{}", domain, port))
                    .await?
                    .find(|a| a.is_ipv4())
                    .ok_or_else(|| ProxyError::DnsResolutionFailed(domain.clone()))
            }
        }
    }

}

#[derive(Debug)]
pub struct Socks5Request {
    pub cmd: Command,
    pub addr: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    TcpConnect = 0x01,
    UdpAssociate = 0x03,
}

impl Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Command::TcpConnect),
            0x03 => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCode {
    Success = 0x00,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
}

pub async fn handshake(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let ver = header[0];
    let nmethods = header[1];

    if ver != 0x05 {
        println!("SOCKS版本错误，不支持版本：{ver}");
        return Err(ProxyError::SocksInvalidVersion(ver));
    }

    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(ProxyError::SocksMethodNotSupported);
    }
    stream.write_all(&[0x05, 0x00]).await?;
    Ok(())
}

async fn read_address(stream: &mut TcpStream, atyp: u8) -> Result<Address> {
    // Build a buffer starting with ATYP + raw address bytes,
    // then delegate to Address::from_socks5.
    let extra = match atyp {
        0x01 => 6,           // 4-byte IPv4 + 2-byte port
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            len_buf[0] as usize + 3 // domain-len(1) + domain + port(2)
        }
        0x04 => 18,          // 16-byte IPv6 + 2-byte port
        _ => return Err(ProxyError::SocksInvalidAddressType(atyp)),
    };
    let mut buf = vec![atyp];
    buf.resize(1 + extra, 0);
    stream.read_exact(&mut buf[1..]).await?;
    Address::from_socks5(&buf).map(|(a, _)| a)
}

pub async fn read_request(stream: &mut TcpStream) -> Result<Socks5Request> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let ver = header[0];
    let cmd = header[1];
    let atyp = header[3];

    if ver != 0x05 {
        println!("SOCKS版本错误，不支持版本：{ver}");
        return Err(ProxyError::SocksInvalidVersion(ver));
    }

    let cmd = Command::from_u8(cmd)
        .ok_or(ProxyError::SocksInvalidCommand(cmd))?;

    let addr = read_address(stream, atyp).await?;

    Ok(Socks5Request { cmd, addr })
}

pub async fn write_reply(
    stream: &mut TcpStream,
    code: ReplyCode,
    bind_addr: &Address,
) -> Result<()> {
    let addr_bytes = bind_addr.to_socks5_bytes();
    let mut reply = Vec::with_capacity(4 + addr_bytes.len());
    reply.extend_from_slice(&[0x05, code as u8, 0x00]);
    reply.extend_from_slice(&addr_bytes);
    stream.write_all(&reply).await?;
    Ok(())
}
