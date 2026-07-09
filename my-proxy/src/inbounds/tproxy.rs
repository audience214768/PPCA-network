use std::net::{SocketAddr};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;
use std::os::unix::io::AsRawFd;
use crate::error::Result;
use crate::relay;


pub async fn run_tproxy_tcp(bind_addr: SocketAddr) -> Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    // IP_TRANSPARENT required for TPROXY to bind to non-local addresses
    let fd = socket.as_raw_fd();
    let enable: libc::c_int = 1;
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(crate::error::ProxyError::Io(std::io::Error::last_os_error()));
        }
    }

    socket.bind(&bind_addr.into())?;
    socket.listen(1024)?;

    let listener = tokio::net::TcpListener::from_std(socket.into())?;
    println!("TPROXY TCP 透明代理已启动：{}", bind_addr);

    loop {
        let (client_stream, _peer) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_tproxy_connection(client_stream).await {
                println!("TPROXY 连接处理异常：{:?}", e);
            }
        });
    }
}

async fn handle_tproxy_connection(mut client_stream: TcpStream) -> Result<()> {
    let original_addr = client_stream.local_addr()?;
    let mut server_stream = TcpStream::connect(original_addr).await?;
    println!("TPROXY → 目标服务器：{}", original_addr);
    
    relay::tcp::relay(&mut client_stream, &mut server_stream).await?;
    println!("TPROXY 透传结束");
    Ok(())
}
