use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::error::Result;
use crate::socks5_proto::Address;

pub struct UdpRelay {
    socket: UdpSocket,
    client: Option<SocketAddr>,
    seen: HashMap<SocketAddr, Instant>,
    idle_timeout: Duration,
}

impl UdpRelay {
    pub fn new(socket: UdpSocket, idle_timeout: Duration) -> Self {
        Self {
            socket,
            client: None,
            seen: HashMap::new(),
            idle_timeout,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 65536];
        loop {
            let (n, peer) = self.socket.recv_from(&mut buf).await?;

            if Some(peer) == self.client || self.client.is_none() {
                self.handle_client_packet(&buf[..n], peer).await?;
            } else {
                // Full Cone
                self.handle_server_packet(&buf[..n], peer).await?;
            }

            self.cleanup();
        }
    }

    async fn handle_client_packet(
        &mut self,
        data: &[u8],
        peer: SocketAddr,
    ) -> Result<()> {
        if data.len() < 10 {
            return Ok(());
        }
        let frag = data[2];
        if frag != 0x00 {
            return Ok(());
        }

        let (addr, consumed) = match Address::from_socks5(&data[3..]) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let payload = &data[3 + consumed..];

        if self.client.is_none() {
            self.client = Some(peer);
            println!("UDP relay client: {peer}");
        }

        let target = addr.resolve_ipv4().await?;
        println!("UDP relay → {target}");

        self.socket.send_to(payload, target).await?;
        self.seen.insert(target, Instant::now());
        Ok(())
    }

    async fn handle_server_packet(
        &mut self,
        data: &[u8],
        peer: SocketAddr,
    ) -> Result<()> {
        let n = data.len();
        let mut reply = vec![0u8; 10 + n];
        reply[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        match peer {
            SocketAddr::V4(v4) => {
                reply[4..8].copy_from_slice(&v4.ip().octets());
                reply[8..10].copy_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(_) => return Ok(()),
        }
        reply[10..].copy_from_slice(data);

        let client = self.client.unwrap();
        self.socket.send_to(&reply, client).await?;
        self.seen.insert(peer, Instant::now());
        Ok(())
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.seen
            .retain(|_, t| now.duration_since(*t) < self.idle_timeout);
    }
}
