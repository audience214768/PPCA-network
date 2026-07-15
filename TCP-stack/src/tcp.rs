//! TCP protocol — segment parsing, state machine, connection management.
//!
//! Phase 4: 3-way handshake (server-side passive open).
//! LISTEN → SYN-RECEIVED → ESTABLISHED

use crate::util::checksum;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Constants ──

pub const TCP_HDR_LEN: usize = 20;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[allow(unused)]
const DEFAULT_MSS: u16 = 1460;
pub const DEFAULT_WINDOW: u16 = 65535;
const INITIAL_RTO: Duration = Duration::from_secs(1);
const MAX_RETRANSMITS: u32 = 5;
const MAX_RTO: Duration = Duration::from_secs(60);

// ── TCP Header ──

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub _data_offset: u8,   // high nibble × 4 = header length
    pub flags: u8,
    pub window: u16,
    pub _checksum: u16,
    pub _urgent: u16,
}

pub fn parse_tcp(data: &[u8]) -> Option<(TcpHeader, &[u8])> {
    if data.len() < TCP_HDR_LEN {
        return None;
    }
    let data_offset = data[12] >> 4;
    let hdr_len = data_offset as usize * 4;
    if hdr_len < TCP_HDR_LEN || data.len() < hdr_len {
        return None;
    }

    Some((
        TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            _data_offset: data_offset,
            flags: data[13],
            window: u16::from_be_bytes([data[14], data[15]]),
            _checksum: u16::from_be_bytes([data[16], data[17]]),
            _urgent: u16::from_be_bytes([data[18], data[19]]),
        },
        &data[hdr_len..],
    ))
}

pub fn build_tcp_header(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
) -> Vec<u8> {
    let mut buf = vec![0u8; TCP_HDR_LEN];
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack.to_be_bytes());
    buf[12] = 5 << 4; // data_offset = 5 (20 bytes, no options)
    buf[13] = flags;
    buf[14..16].copy_from_slice(&window.to_be_bytes());
    // checksum and urgent pointer left as 0 (caller fills checksum)
    buf
}

/// Build a TCP segment (header + payload) with checksum including pseudo-header.
pub fn build_tcp_segment(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut header = build_tcp_header(src_port, dst_port, seq, ack, flags, window);
    let tcp_len = TCP_HDR_LEN + payload.len();

    // Pseudo-header: 12 bytes
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(6); // TCP protocol
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());

    // Full segment for checksum: pseudo-header + header + payload
    let mut full = Vec::with_capacity(12 + tcp_len);
    full.extend_from_slice(&pseudo);
    full.extend_from_slice(&header);
    full.extend_from_slice(payload);

    let cs = checksum(&full);
    header[16..18].copy_from_slice(&cs.to_be_bytes());

    // Final segment: header + payload
    let mut seg = header;
    seg.extend_from_slice(payload);
    seg
}

pub fn verify_tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], segment: &[u8]) -> bool {
    let tcp_len = segment.len();
    let mut pseudo = Vec::with_capacity(12); //prevent the src and dst from being modifyied
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(6); // TCP protocol
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());

    let mut full = Vec::with_capacity(12 + tcp_len);
    full.extend_from_slice(&pseudo);
    full.extend_from_slice(segment);

    checksum(&full) == 0
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    #[allow(unused)]SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

// ── TCB (Transmission Control Block) ──

pub struct Tcb {
    // Connection identity
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,

    // State
    pub state: TcpState,

    // Send sequence variables (RFC 793)
    pub iss: u32,        // initial send sequence number
    pub snd_una: u32,    // oldest unacknowledged sequence number
    pub snd_nxt: u32,    // next sequence number to send
    pub snd_wnd: u16,    // peer's advertised window

    // Receive sequence variables (RFC 793)
    pub irs: u32,        // initial receive sequence number
    pub rcv_nxt: u32,    // next expected sequence number
    pub _rcv_wnd: u16,    // our advertised window

    // Retransmission
    pub rto: Duration,
    pub retransmit_at: Option<Instant>,
    pub retransmit_count: u32,

    // Send buffer: all unacked application data.
    // Offset in seq space: starts at (iss + 1) for client, (iss + 1) for server.
    pub send_buffer: Vec<u8>,
    pub recv_buffer: Vec<u8>,
}

impl Tcb {
    fn new_server(
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            state: TcpState::Listen,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            irs: 0,
            rcv_nxt: 0,
            _rcv_wnd: DEFAULT_WINDOW,
            rto: INITIAL_RTO,
            retransmit_at: None,
            retransmit_count: 0,
            send_buffer: Vec::new(),
            recv_buffer: Vec::new(),
        }
    }
}

/// 4-tuple key for connection lookup.
pub type ConnKey = ([u8; 4], u16, [u8; 4], u16); // (local_ip, local_port, remote_ip, remote_port)

pub struct TcpManager {
    connections: HashMap<ConnKey, Tcb>,
}

impl TcpManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Process an incoming TCP segment. Returns any segment that should be sent back.
    pub fn process(
        &mut self,
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        tcp_hdr: &TcpHeader,
        payload: &[u8],
        now: Instant,
    ) -> (Option<ConnKey>, Vec<OutgoingSegment>) {
        let key: ConnKey = (
            local_ip,
            tcp_hdr.dst_port,
            remote_ip,
            tcp_hdr.src_port,
        );

        let outgoing = if let Some(tcb) = self.connections.get_mut(&key) {
            process_existing_tcb(tcb, tcp_hdr, payload, now)
        } else {
            // No matching connection and not a SYN to a listening port → RST
            if tcp_hdr.flags & TCP_RST == 0 {
                let rst = OutgoingSegment {
                    flags: TCP_RST | TCP_ACK,
                    seq: if tcp_hdr.flags & TCP_ACK != 0 {
                        tcp_hdr.ack
                    } else {
                        0
                    },
                    ack: tcp_hdr.seq.wrapping_add(payload.len() as u32 + if tcp_hdr.flags & TCP_SYN != 0 { 1 } else { 0 }),
                    payload: Vec::new(),
                    dst_port: tcp_hdr.src_port,
                };
                return (None, vec![rst]);
            }
            return (None, vec![]);
        };

        (Some(key), outgoing)
    }
}

fn process_existing_tcb(
    tcb: &mut Tcb,
    header: &TcpHeader,
    payload: &[u8],
    now: Instant,
) -> Vec<OutgoingSegment> {
        match tcb.state {
            TcpState::SynReceived => {
                // Expecting ACK of our SYN+ACK
                if header.flags & TCP_ACK != 0 {
                    if header.ack == tcb.snd_nxt {
                        tcb.state = TcpState::Established;
                        tcb.rcv_nxt = header.seq.wrapping_add(1); // consume the SYN
                        tcb.snd_una = header.ack;
                        tcb.retransmit_at = None;
                        tcb.retransmit_count = 0;
                        println!(
                            "TCP: connection established {}:{} <-> {}:{}",
                            ip_str(tcb.local_ip),
                            tcb.local_port,
                            ip_str(tcb.remote_ip),
                            tcb.remote_port,
                        );
                        return vec![];
                    }
                }
                // Invalid or wrong ACK → re-send SYN+ACK if timer expired
                if tcb.retransmit_at.map_or(false, |t| now >= t) {
                    return vec![OutgoingSegment {
                        flags: TCP_SYN | TCP_ACK,
                        seq: tcb.iss,
                        ack: tcb.rcv_nxt,
                        payload: Vec::new(),
                        dst_port: tcb.remote_port,
                    }];
                }
                vec![]
            }
            TcpState::Established => {
                let seg_len = payload.len() as u32;
                let syn_flag = if header.flags & TCP_SYN != 0 { 1 } else { 0 };
                let fin_flag = if header.flags & TCP_FIN != 0 { 1 } else { 0 };

                let mut outgoing = Vec::new();

                // Process ACK: advance snd_una, trim send_buffer
                if header.flags & TCP_ACK != 0 {
                    let ack_val = header.ack;
                    if ack_val.wrapping_sub(tcb.snd_una) > 0 && ack_val.wrapping_sub(tcb.snd_nxt) <= 0 {
                        let acked = ack_val.wrapping_sub(tcb.snd_una) as usize;
                        let trim = acked.min(tcb.send_buffer.len());
                        if trim > 0 {
                            tcb.send_buffer.drain(..trim);
                        }
                        tcb.snd_una = ack_val;
                        // Stop retransmit timer if all data ACKed
                        if tcb.snd_una == tcb.snd_nxt {
                            tcb.retransmit_at = None;
                            tcb.retransmit_count = 0;
                        }
                    }
                }

                // Process incoming data
                if seg_len > 0 || syn_flag != 0 || fin_flag != 0 {
                    if header.seq == tcb.rcv_nxt {
                        if seg_len > 0 {
                            tcb.recv_buffer.extend_from_slice(payload);
                        }
                        tcb.rcv_nxt = header.seq.wrapping_add(seg_len + syn_flag + fin_flag);

                        outgoing.push(OutgoingSegment {
                            flags: TCP_ACK,
                            seq: tcb.snd_nxt,
                            ack: tcb.rcv_nxt,
                            payload: Vec::new(),
                            dst_port: tcb.remote_port,
                        });

                        if fin_flag != 0 {
                            tcb.state = TcpState::CloseWait;
                            println!(
                                "TCP: FIN from {}:{} (passive close, now CloseWait)",
                                ip_str(tcb.remote_ip), tcb.remote_port,
                            );
                        }
                    }
                }
                outgoing
            }
            TcpState::CloseWait => {
                // Waiting for application to call close() — just ACK any data
                let seg_len = payload.len() as u32;
                if seg_len > 0 && header.seq == tcb.rcv_nxt {
                    tcb.recv_buffer.extend_from_slice(payload);
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(seg_len);
                    return vec![OutgoingSegment {
                        flags: TCP_ACK,
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        payload: Vec::new(),
                        dst_port: tcb.remote_port,
                    }];
                }
                vec![]
            }
            TcpState::LastAck => {
                // Waiting for ACK of our FIN
                if header.flags & TCP_ACK != 0 {
                    tcb.state = TcpState::Closed;
                    tcb.retransmit_at = None;
                    println!(
                        "TCP: connection closed {}:{} -> {}:{}",
                        ip_str(tcb.local_ip), tcb.local_port,
                        ip_str(tcb.remote_ip), tcb.remote_port,
                    );
                }
                vec![]
            }
            TcpState::FinWait1 => {
                // Sent FIN, waiting for ACK
                let seg_len = payload.len() as u32;
                if header.flags & TCP_ACK != 0 {
                    if header.ack == tcb.snd_nxt {
                        tcb.snd_una = header.ack;
                        tcb.retransmit_at = None;
                        tcb.retransmit_count = 0;
                        if header.flags & TCP_FIN != 0 {
                            // Simultaneous close: FIN+ACK received
                            tcb.rcv_nxt = header.seq.wrapping_add(seg_len + 1);
                            tcb.state = TcpState::TimeWait;
                            tcb.retransmit_at = Some(now + Duration::from_secs(60));
                            return vec![OutgoingSegment {
                                flags: TCP_ACK,
                                seq: tcb.snd_nxt,
                                ack: tcb.rcv_nxt,
                                payload: Vec::new(),
                                dst_port: tcb.remote_port,
                            }];
                        }
                        tcb.state = TcpState::FinWait2;
                    }
                } else if header.flags & TCP_FIN != 0 {
                    // FIN before ACK
                    tcb.rcv_nxt = header.seq.wrapping_add(seg_len + 1);
                    tcb.state = TcpState::Closing;
                    return vec![OutgoingSegment {
                        flags: TCP_ACK,
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        payload: Vec::new(),
                        dst_port: tcb.remote_port,
                    }];
                }
                // Buffer any data
                if seg_len > 0 && header.seq == tcb.rcv_nxt {
                    tcb.recv_buffer.extend_from_slice(payload);
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(seg_len);
                }
                vec![]
            }
            TcpState::FinWait2 => {
                // ACK of FIN received, waiting for peer's FIN
                let seg_len = payload.len() as u32;
                let fin_flag = if header.flags & TCP_FIN != 0 { 1 } else { 0 };
                if fin_flag != 0 && header.seq == tcb.rcv_nxt {
                    tcb.rcv_nxt = header.seq.wrapping_add(seg_len + 1);
                    tcb.state = TcpState::TimeWait;
                    tcb.retransmit_at = Some(now + Duration::from_secs(60));
                    return vec![OutgoingSegment {
                        flags: TCP_ACK,
                        seq: tcb.snd_nxt,
                        ack: tcb.rcv_nxt,
                        payload: Vec::new(),
                        dst_port: tcb.remote_port,
                    }];
                }
                if seg_len > 0 && header.seq == tcb.rcv_nxt {
                    tcb.recv_buffer.extend_from_slice(payload);
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(seg_len);
                }
                vec![]
            }
            TcpState::SynSent => {
                // Expecting SYN+ACK from server
                if header.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK {
                    if header.ack == tcb.snd_nxt {
                        tcb.irs = header.seq;
                        tcb.rcv_nxt = header.seq.wrapping_add(1);
                        tcb.snd_una = header.ack;
                        tcb.snd_wnd = header.window;
                        tcb.state = TcpState::Established;
                        tcb.retransmit_at = None;
                        tcb.retransmit_count = 0;
                        println!(
                            "TCP: connection established (active) {}:{} -> {}:{}",
                            ip_str(tcb.local_ip), tcb.local_port,
                            ip_str(tcb.remote_ip), tcb.remote_port,
                        );
                        // Send ACK to complete handshake
                        return vec![OutgoingSegment {
                            flags: TCP_ACK,
                            seq: tcb.snd_nxt,
                            ack: tcb.rcv_nxt,
                            payload: Vec::new(),
                            dst_port: tcb.remote_port,
                        }];
                    }
                } else if header.flags & TCP_RST != 0 {
                    tcb.state = TcpState::Closed;
                    println!(
                        "TCP: connection refused {}:{}",
                        ip_str(tcb.remote_ip), tcb.remote_port,
                    );
                }
                vec![]
            }
            TcpState::Closing => {
                // Sent FIN, received FIN, waiting for ACK of our FIN
                if header.flags & TCP_ACK != 0 && header.ack == tcb.snd_nxt {
                    tcb.state = TcpState::TimeWait;
                    tcb.retransmit_at = Some(now + Duration::from_secs(60));
                    tcb.retransmit_count = 0;
                }
                vec![]
            }
            _ => vec![],
        }
    }

impl TcpManager {
    /// Check for retransmission timeouts. Returns segments that need re-sending.
    pub fn poll_retransmit(
        &mut self,
        now: Instant,
    ) -> Vec<(ConnKey, OutgoingSegment)> {
        let mut retransmits = Vec::new();
        for (key, tcb) in &mut self.connections {
            if let Some(deadline) = tcb.retransmit_at {
                if now >= deadline {
                    if tcb.retransmit_count >= MAX_RETRANSMITS {
                        // Too many retransmissions — kill connection
                        tcb.state = TcpState::Closed;
                        println!(
                            "TCP: connection {}:{} -> {}:{} timed out ({} retransmits)",
                            ip_str(tcb.local_ip),
                            tcb.local_port,
                            ip_str(tcb.remote_ip),
                            tcb.remote_port,
                            tcb.retransmit_count,
                        );
                        continue;
                    }
                    tcb.retransmit_at = Some(now + tcb.rto);
                    tcb.rto = (tcb.rto * 2).min(MAX_RTO);
                    tcb.retransmit_count += 1;

                    let seg = build_retransmit(tcb);
                    retransmits.push((*key, seg));
                }
            }
        }

        // Remove closed connections; also expire TimeWait
        self.connections.retain(|_, tcb| {
            if tcb.state == TcpState::Closed {
                return false;
            }
            if tcb.state == TcpState::TimeWait {
                if let Some(expiry) = tcb.retransmit_at {
                    if now >= expiry {
                        return false;
                    }
                }
            }
            true
        });

        retransmits
    }

    /// Get a reference to a TCB by key.
    pub fn get(&self, key: &ConnKey) -> Option<&Tcb> {
        self.connections.get(key)
    }

    /// Get a mutable reference to a TCB by key.
    pub fn get_mut(&mut self, key: &ConnKey) -> Option<&mut Tcb> {
        self.connections.get_mut(key)
    }

    /// Start retransmission timer for this connection if not already running.
    pub fn record_sent(&mut self, key: &ConnKey, now: Instant) {
        if let Some(tcb) = self.connections.get_mut(key) {
            if tcb.retransmit_at.is_none() {
                tcb.retransmit_at = Some(now + tcb.rto);
            }
        }
    }

    /// Drain received data from a connection's buffer.
    pub fn drain_data(&mut self, key: &ConnKey) -> Vec<u8> {
        let tcb = match self.connections.get_mut(key) {
            Some(t) => t,
            None => return Vec::new(),
        };
        std::mem::take(&mut tcb.recv_buffer)
    }

    /// Check if a connection has data available to read.

    /// Check if a connection is in CloseWait (app should call close).

    /// Initiate an active close: send FIN.
    pub fn close(&mut self, key: &ConnKey, now: Instant) -> Vec<OutgoingSegment> {
        let tcb = match self.connections.get_mut(key) {
            Some(t) => t,
            None => return vec![],
        };
        match tcb.state {
            TcpState::Established => {
                tcb.state = TcpState::FinWait1;
                let seg = OutgoingSegment {
                    flags: TCP_FIN | TCP_ACK,
                    seq: tcb.snd_nxt,
                    ack: tcb.rcv_nxt,
                    payload: Vec::new(),
                    dst_port: tcb.remote_port,
                };
                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                tcb.retransmit_at = Some(now + tcb.rto);
                println!(
                    "TCP: active close {}:{} -> {}:{} (FIN sent)",
                    ip_str(tcb.local_ip), tcb.local_port,
                    ip_str(tcb.remote_ip), tcb.remote_port,
                );
                vec![seg]
            }
            TcpState::CloseWait => {
                tcb.state = TcpState::LastAck;
                let seg = OutgoingSegment {
                    flags: TCP_FIN | TCP_ACK,
                    seq: tcb.snd_nxt,
                    ack: tcb.rcv_nxt,
                    payload: Vec::new(),
                    dst_port: tcb.remote_port,
                };
                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                tcb.retransmit_at = Some(now + tcb.rto);
                println!(
                    "TCP: closing {}:{} -> {}:{} (FIN from CloseWait)",
                    ip_str(tcb.local_ip), tcb.local_port,
                    ip_str(tcb.remote_ip), tcb.remote_port,
                );
                vec![seg]
            }
            TcpState::Closed | TcpState::TimeWait | TcpState::Listen => vec![],
            _ => {
                // Force close with RST for other states
                tcb.state = TcpState::Closed;
                vec![OutgoingSegment {
                    flags: TCP_RST,
                    seq: tcb.snd_nxt,
                    ack: 0,
                    payload: Vec::new(),
                    dst_port: tcb.remote_port,
                }]
            }
        }
    }

    /// Check which connections have received data (for echo).

    /// Find an established connection on the given local port.

    /// Find the source port for a connection matching remote IP and port.
    pub fn find_src_port(&self, remote_ip: [u8; 4], remote_port: u16) -> Option<u16> {
        self.connections
            .iter()
            .find(|(k, _)| k.2 == remote_ip && k.3 == remote_port)
            .map(|(k, _)| k.1)
    }

    /// Close a connection (active or passive close).
    pub fn close_conn(&mut self, key: &ConnKey, now: Instant) -> Vec<OutgoingSegment> {
        self.close(key, now)
    }

    /// Initiate an active connection (client SYN).
    pub fn initiate_connect(
        &mut self,
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        remote_port: u16,
        now: Instant,
    ) -> (Option<ConnKey>, Vec<OutgoingSegment>) {
        let local_port = self.next_ephemeral();
        let key: ConnKey = (local_ip, local_port, remote_ip, remote_port);

        if let Some(tcb) = self.connections.get(&key) {
            if tcb.state == TcpState::Established {
                return (Some(key), vec![]);
            }
            if tcb.state == TcpState::SynSent {
                return (Some(key), vec![]);
            }
        }

        let iss = rand_seq();
        let mut tcb = Tcb::new_server(local_ip, remote_ip, local_port, remote_port);
        tcb.state = TcpState::SynSent;
        tcb.iss = iss;
        tcb.snd_una = iss;
        tcb.snd_nxt = iss.wrapping_add(1);
        tcb.retransmit_at = Some(now + INITIAL_RTO);
        tcb.rto = INITIAL_RTO;

        println!("TCP: connecting to {}:{}", ip_str(remote_ip), remote_port);
        self.connections.insert(key, tcb);

        (
            Some(key),
            vec![OutgoingSegment {
                flags: TCP_SYN,
                seq: iss,
                ack: 0,
                payload: Vec::new(),
                dst_port: remote_port,
            }],
        )
    }

    /// Iterate over all connections.

    fn next_ephemeral(&self) -> u16 {
        for port in 40000..60000 {
            if !self.connections.keys().any(|k| k.1 == port) {
                return port;
            }
        }
        40000
    }

}

/// An outgoing TCP segment to be wrapped in IP and sent.
#[derive(Debug)]
pub struct OutgoingSegment {
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub payload: Vec<u8>,
    pub dst_port: u16,
}

// ── Helpers ──

pub fn rand_seq() -> u32 {
    // Simple pseudo-random ISS based on time
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (t & 0xFFFF_FFFF) as u32
}

/// Build an OutgoingSegment for retransmission from the TCB state.
fn build_retransmit(tcb: &Tcb) -> OutgoingSegment {
    match tcb.state {
        TcpState::SynSent => OutgoingSegment {
            flags: TCP_SYN,
            seq: tcb.iss,
            ack: 0,
            payload: Vec::new(),
            dst_port: tcb.remote_port,
        },
        TcpState::SynReceived => OutgoingSegment {
            flags: TCP_SYN | TCP_ACK,
            seq: tcb.iss,
            ack: tcb.rcv_nxt,
            payload: Vec::new(),
            dst_port: tcb.remote_port,
        },
        TcpState::Established | TcpState::CloseWait => {
            // Retransmit oldest unacked data from send_buffer
            let offset = tcb.snd_una.wrapping_sub(tcb.iss.wrapping_add(1)) as usize;
            let payload = if offset < tcb.send_buffer.len() {
                tcb.send_buffer[offset..].to_vec()
            } else {
                Vec::new()
            };
            OutgoingSegment {
                flags: if payload.is_empty() { TCP_ACK } else { TCP_PSH | TCP_ACK },
                seq: tcb.snd_una,
                ack: tcb.rcv_nxt,
                payload,
                dst_port: tcb.remote_port,
            }
        }
        TcpState::FinWait1 | TcpState::LastAck | TcpState::Closing => OutgoingSegment {
            flags: TCP_FIN | TCP_ACK,
            seq: tcb.snd_nxt.wrapping_sub(1), // FIN was already counted
            ack: tcb.rcv_nxt,
            payload: Vec::new(),
            dst_port: tcb.remote_port,
        },
        _ => OutgoingSegment {
            flags: TCP_ACK,
            seq: tcb.snd_una,
            ack: tcb.rcv_nxt,
            payload: Vec::new(),
            dst_port: tcb.remote_port,
        },
    }
}

fn ip_str(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_build_roundtrip() {
        let header = build_tcp_header(8080, 80, 1000, 2000, TCP_SYN | TCP_ACK, 65535);
        let (header, payload) = parse_tcp(&header).expect("should parse");
        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header.seq, 1000);
        assert_eq!(header.ack, 2000);
        assert_eq!(header.flags, TCP_SYN | TCP_ACK);
        assert_eq!(header.window, 65535);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_tcp_checksum() {
        let seg = build_tcp_segment(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            8080,
            80,
            100,
            200,
            TCP_SYN | TCP_ACK,
            65535,
            b"",
        );
        assert!(verify_tcp_checksum([10, 0, 0, 2], [10, 0, 0, 1], &seg));
    }

    #[test]
    fn test_tcp_segment_with_payload() {
        let seg = build_tcp_segment(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            8080,
            80,
            100,
            200,
            TCP_PSH | TCP_ACK,
            65535,
            b"hello",
        );
        assert!(verify_tcp_checksum([10, 0, 0, 2], [10, 0, 0, 1], &seg));
        let (header, payload) = parse_tcp(&seg).expect("should parse");
        assert_eq!(header.flags, TCP_PSH | TCP_ACK);
        assert_eq!(payload, b"hello");
    }

}
