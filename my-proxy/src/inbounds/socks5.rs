use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::error::Result;
use crate::socks5_proto::{Address, Command, ReplyCode, write_reply, handshake, read_request};
use crate::relay::{self, udp::UdpRelay};

const ZERO_ADDR: Address = Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0), 0);

pub async fn run_socks5_tcp(bind_addr: SocketAddr, udp_idle_timeout: Duration) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    println!("SOCKS5 代理已启动：{}", bind_addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, udp_idle_timeout).await {
                println!("连接 [{}] 处理异常：{:?}", addr, e);
            }
        });
    }
}

async fn handle_client(mut client_stream: TcpStream, udp_idle_timeout: Duration) -> Result<()> {
    handshake(&mut client_stream).await?;
    let request = read_request(&mut client_stream).await?;

    match request.cmd {
        Command::TcpConnect => {
            let addr = request.addr;
            println!("SOCKS5 CONNECT → {addr:?}");

            let server_addr = match addr.resolve().await {
                Ok(a) => a,
                Err(e) => {
                    println!("DNS 失败: {e:?}");
                    let _ = write_reply(&mut client_stream, ReplyCode::HostUnreachable, &ZERO_ADDR).await;
                    return Err(e);
                }
            };

            let mut server_stream = match TcpStream::connect(server_addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    println!("连接失败: {e:?}");
                    let _ = write_reply(&mut client_stream, ReplyCode::ConnectionRefused, &ZERO_ADDR).await;
                    return Err(e.into());
                }
            };

            let _ = write_reply(&mut client_stream, ReplyCode::Success, &ZERO_ADDR).await;
            relay::tcp::relay(&mut client_stream, &mut server_stream).await?;
            println!("SOCKS5 透传结束");
        }
        Command::UdpAssociate => {
            let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
            let port = udp_socket.local_addr()?.port();

            let local_ip = match client_stream.local_addr()? {
                SocketAddr::V4(v4) => *v4.ip(),
                SocketAddr::V6(_) => Ipv4Addr::new(127, 0, 0, 1),
            };
            let bind_addr = Address::Ipv4(local_ip, port);
            write_reply(&mut client_stream, ReplyCode::Success, &bind_addr).await?;

            println!("UDP relay on :{port}");
            let mut relay = UdpRelay::new(udp_socket, udp_idle_timeout);
            let mut tmp_buf = [0u8; 1];
            tokio::select! {
                r = client_stream.read(&mut tmp_buf) => {
                    match r {
                        Ok(0) => println!("TCP 关闭"),
                        Ok(_) => println!("TCP 异常数据"),
                        Err(e) => println!("TCP 错误: {e:?}"),
                    }
                }
                r = relay.run() => {
                    if let Err(e) = r {
                        println!("UDP relay 异常: {e:?}");
                    }
                }
            }
        }
    }
    Ok(())
}
