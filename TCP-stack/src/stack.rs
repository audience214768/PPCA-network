

use crate::arp::{self, ArpCache};
use crate::ethernet::{self, BROADCAST_MAC, ETH_TYPE_ARP, ETH_TYPE_IPV4};
use crate::ip;
use crate::socket::TcpSocket;
use crate::tap::TapDevice;
use crate::tcp::{self, ConnKey, TcpManager, TcpState, DEFAULT_WINDOW};

use std::io;
use std::time::Instant;

pub struct TcpStack {
    tap: TapDevice,
    arp: ArpCache,
    tcp: TcpManager,
    pub our_ip: [u8; 4],
    pub our_mac: [u8; 6],
    now: Instant,
}

impl TcpStack {
    pub fn new(tap_name: &str, our_ip: [u8; 4]) -> io::Result<Self> {
        let tap = TapDevice::open(tap_name)?;
        let our_mac = tap.mac;
        Ok(Self {
            tap,
            arp: ArpCache::new(),
            tcp: TcpManager::new(),
            our_ip,
            our_mac,
            now: Instant::now(),
        })
    }

    pub fn connect(&mut self, remote_ip: [u8; 4], remote_port: u16) -> Option<TcpSocket> {
        let (sock, outgoing) = 
            crate::socket::connect(
                &mut self.tcp, 
                self.our_ip, 
                remote_ip, 
                remote_port, 
                self.now
            );
        let key = sock.as_ref().map(|s| s.key);
        self.send_segments_with_key(outgoing, key, remote_ip);
        sock
    }

    pub fn send(&mut self, sock: &TcpSocket, data: &[u8]) -> usize {
        let len = data.len();
        let segs = crate::socket::send(&mut self.tcp, sock, data);
        let remote_ip = self.tcp.get(&sock.key).map(|t| t.remote_ip).unwrap_or([0; 4]);
        self.send_segments_with_key(segs, Some(sock.key), remote_ip);
        len
    }

    pub fn recv(&mut self, sock: &TcpSocket) -> Vec<u8> {
        crate::socket::recv(&mut self.tcp, sock)
    }

    pub fn close(&mut self, sock: &TcpSocket) {
        let segs = crate::socket::close(&mut self.tcp, sock, self.now);
        let remote_ip = self.tcp.get(&sock.key).map(|t| t.remote_ip).unwrap_or([0; 4]);
        self.send_segments_with_key(segs, Some(sock.key), remote_ip);
    }

    pub fn is_established(&self, sock: &TcpSocket) -> bool {
        matches!(self.tcp.get(&sock.key).map(|t| t.state), Some(TcpState::Established))
    }

    pub fn is_closed(&self, sock: &TcpSocket) -> bool {
        matches!(self.tcp.get(&sock.key).map(|t| t.state), Some(TcpState::Closed) | None)
    }

    pub fn state(&self, sock: &TcpSocket) -> Option<TcpState> {
        self.tcp.get(&sock.key).map(|t| t.state)
    }

    /// Run one iteration. Drives the whole protocol stack.
    pub fn poll(&mut self) -> io::Result<()> {
        self.now = Instant::now();

        // 1. ARP retry
        self.arp_tick();

        // 2. TCP retransmit
        self.tcp_retransmit();

        // 3. Read and dispatch all available frames
        let mut buf = vec![0u8; 65536];
        loop {
            match self.tap.read_frame(&mut buf) {
                Ok(n) => self.dispatch(&buf[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn arp_tick(&mut self) {
        let tick = self.arp.tick(self.now);
        for ip in &tick.retry_ips {
            let req = arp::build_arp_request(self.our_mac, self.our_ip, *ip);
            let frame = ethernet::build_frame(
                BROADCAST_MAC, 
                self.our_mac, 
                ETH_TYPE_ARP, 
                &req
            );
            let _ = self.tap.write_frame(&frame);
            self.arp.record_request(*ip, self.now);
        }
        for ip in &tick.timed_out_ips {
            println!("> ARP: timeout for {}", ip_str(*ip));
        }
    }

    fn tcp_retransmit(&mut self) {
        let retrans = self.tcp.poll_retransmit(self.now);
        for (key, seg) in &retrans {
            let seg_bytes = tcp::build_tcp_segment(
                self.our_ip, 
                key.2, 
                key.1, 
                seg.dst_port, 
                seg.seq, 
                seg.ack, 
                seg.flags, 
                DEFAULT_WINDOW, 
                &seg.payload
            );
            let ip_packet = ip::build_ipv4(
                self.our_ip, 
                key.2, 
                ip::IP_PROTO_TCP, 
                64, 
                &seg_bytes
            );
            self.send_frame(key.2, ip_packet, Some(*key));
        }
    }

    fn dispatch(&mut self, data: &[u8]) {
        let (header, payload) = match ethernet::parse_frame(data) {
            Some(v) => v,
            None => return,
        };
        match header.ethertype {
            ETH_TYPE_ARP => self.handle_arp(&header, payload),
            ETH_TYPE_IPV4 => self.handle_ipv4(&header, payload),
            _ => {}
        }
    }

    fn handle_arp(&mut self, _hdr: &ethernet::EthernetHdr, payload: &[u8]) {
        let pkt = match arp::parse_arp(payload) {
            Some(p) => p,
            None => return,
        };
        self.arp.learn(pkt.spa, pkt.sha);

        if pkt.oper == arp::ARP_OP_REQUEST && pkt.tpa == self.our_ip {
            println!(
                "> ARP: who-has {}? tell {}",
                ip_str(pkt.tpa),
                ip_str(pkt.spa),
            );
            let reply = arp::build_arp_reply(self.our_mac, self.our_ip, pkt.sha, pkt.spa);
            let frame = ethernet::build_frame(pkt.sha, self.our_mac, ETH_TYPE_ARP, &reply);
            let _ = self.tap.write_frame(&frame);
        } else if pkt.oper == arp::ARP_OP_REPLY {
            println!(
                "> ARP: reply {} is-at {}",
                ip_str(pkt.spa),
                mac_str(pkt.sha),
            );
            let queued = self.arp.insert(pkt.spa, pkt.sha);
            for qpkt in queued {
                let frame = ethernet::build_frame(pkt.sha, self.our_mac, ETH_TYPE_IPV4, &qpkt);
                let _ = self.tap.write_frame(&frame);
                println!("  -> sent {} queued packet(s)", 1);
            }
        }
    }

    fn handle_ipv4(&mut self, header: &ethernet::EthernetHdr, payload: &[u8]) {
        let (ip_hdr, ip_payload) = match ip::parse_ipv4(payload) {
            Some(v) => v,
            None => return,
        };
        self.arp.learn(ip_hdr.src, header.src);

        match ip_hdr.protocol {
            ip::IP_PROTO_ICMP => {
                if let Some(reply) = ip::build_icmp_echo_reply(ip_payload) {
                    let ip_pkt = ip::build_ipv4(
                        self.our_ip, ip_hdr.src, ip::IP_PROTO_ICMP, 64, &reply,
                    );
                    self.send_frame(ip_hdr.src, ip_pkt, None);
                    println!(
                        "> ICMP: echo reply {} -> {}",
                        ip_str(ip_hdr.dst),
                        ip_str(ip_hdr.src),
                    );
                }
            }
            ip::IP_PROTO_TCP => {
                if !tcp::verify_tcp_checksum(ip_hdr.src, ip_hdr.dst, ip_payload) {
                    return;
                }
                let (tcp_hdr, tcp_data) = match tcp::parse_tcp(ip_payload) {
                    Some(v) => v,
                    None => return,
                };
                let (key, outgoing) = self.tcp.process(
                    self.our_ip, ip_hdr.src,
                    &tcp_hdr, tcp_data, self.now,
                );
                self.send_segments_with_key(outgoing, key, ip_hdr.src);
            }
            _ => {}
        }
    }

    /// Send OutgoingSegments: build TCP -> IP -> resolve MAC -> write.
    fn send_segments_with_key(
        &mut self,
        segs: Vec<tcp::OutgoingSegment>,
        key: Option<ConnKey>,
        dst_ip: [u8; 4],
    ) {
        for seg in &segs {
            let src_port = key.map(|k| k.1).or_else(|| {
                self.tcp.find_src_port(dst_ip, seg.dst_port)
            }).unwrap_or(0);
            let seg_bytes = tcp::build_tcp_segment(
                self.our_ip, 
                dst_ip, 
                src_port, 
                seg.dst_port,
                seg.seq, 
                seg.ack, 
                seg.flags, 
                DEFAULT_WINDOW, 
                &seg.payload,
            );
            let ip_packet = ip::build_ipv4(
                self.our_ip, 
                dst_ip, 
                ip::IP_PROTO_TCP, 
                64, 
                &seg_bytes);
            self.send_frame(dst_ip, ip_packet, key);
        }
    }

    fn send_frame(
        &mut self,
        dst_ip: [u8; 4],
        ip_packet: Vec<u8>,
        conn_key: Option<ConnKey>,
    ) {
        if let Some(k) = conn_key {
            self.tcp.record_sent(&k, self.now);
        }

        if let Some(dst_mac) = self.arp.lookup(dst_ip) {
            let frame = ethernet::build_frame(dst_mac, self.our_mac, ETH_TYPE_IPV4, &ip_packet);
            let _ = self.tap.write_frame(&frame);
        } else {
            let is_new = self.arp.queue_packet(dst_ip, ip_packet, self.now);
            if is_new {
                let req = arp::build_arp_request(self.our_mac, self.our_ip, dst_ip);
                let frame = ethernet::build_frame(BROADCAST_MAC, self.our_mac, ETH_TYPE_ARP, &req);
                let _ = self.tap.write_frame(&frame);
                println!("> ARP: who-has {}?", ip_str(dst_ip));
                self.arp.record_request(dst_ip, self.now);
            }
        }
    }

}

fn ip_str(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn mac_str(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
