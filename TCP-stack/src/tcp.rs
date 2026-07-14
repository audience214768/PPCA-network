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
    pub data_offset: u8,   // high nibble × 4 = header length
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
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
            data_offset,
            flags: data[13],
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent: u16::from_be_bytes([data[18], data[19]]),
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

    // But: checksum field is in the header which starts at index 12 in `full`
    // We zero it and compute over everything
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
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
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
    pub rcv_wnd: u16,    // our advertised window

    // Retransmission
    pub rto: Duration,
    pub retransmit_at: Option<Instant>,
    pub retransmit_count: u32,
    /// The last segment we sent that hasn't been ACKed yet (for retransmission).
    pub last_sent: Option<Vec<u8>>,

    // Data buffers (Phase 5+)
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
            rcv_wnd: DEFAULT_WINDOW,
            rto: INITIAL_RTO,
            retransmit_at: None,
            retransmit_count: 0,
            last_sent: None,
            send_buffer: Vec::new(),
            recv_buffer: Vec::new(),
        }
    }
}

/// 4-tuple key for connection lookup.
pub type ConnKey = ([u8; 4], u16, [u8; 4], u16); // (local_ip, local_port, remote_ip, remote_port)

pub struct TcpManager {
    connections: HashMap<ConnKey, Tcb>,
    listeners: HashMap<u16, bool>, // local_port → has a listener
}

/// Result of processing an incoming TCP segment.
pub enum ProcessResult {
    /// Nothing to do (invalid, ignored, etc.)
    None,
    /// Send this TCP segment back (as part of a handshake, ACK, etc.)
    Reply {
        flags: u8,
        ack: u32,
        seq: u32,
        payload: Vec<u8>,
    },
}

impl TcpManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            listeners: HashMap::new(),
        }
    }

    /// Register a listener on the given local port.
    pub fn listen(&mut self, port: u16) {
        self.listeners.insert(port, true);
    }

    /// Check if we're listening on a port.
    pub fn is_listening(&self, port: u16) -> bool {
        self.listeners.contains_key(&port)
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
        } else if tcp_hdr.flags & TCP_SYN != 0 && self.is_listening(tcp_hdr.dst_port) {
            // New SYN → create connection in SYN-RECEIVED
            self.process_new_syn(key, tcp_hdr, now)
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
    hdr: &TcpHeader,
    payload: &[u8],
    now: Instant,
) -> Vec<OutgoingSegment> {
        match tcb.state {
            TcpState::SynReceived => {
                // Expecting ACK of our SYN+ACK
                if hdr.flags & TCP_ACK != 0 {
                    if hdr.ack == tcb.snd_nxt {
                        tcb.state = TcpState::Established;
                        tcb.rcv_nxt = hdr.seq.wrapping_add(1); // consume the SYN
                        tcb.snd_una = hdr.ack;
                        tcb.retransmit_at = None;
                        tcb.retransmit_count = 0;
                        tcb.last_sent = None;
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
                // Invalid or wrong ACK → re-send SYN+ACK if needed
                if let Some(seg) = &tcb.last_sent {
                    if tcb.retransmit_at.map_or(true, |t| now >= t) {
                        let h = parse_tcp(seg).unwrap().0;
                        return vec![OutgoingSegment {
                            flags: h.flags,
                            seq: h.seq,
                            ack: h.ack,
                            payload: Vec::new(),
                            dst_port: tcb.remote_port,
                        }];
                    }
                }
                vec![]
            }
            TcpState::Established => {
                // Phase 5: data handling
                // For now, ACK any incoming data
                let seg_len = payload.len() as u32;
                let syn_flag = if hdr.flags & TCP_SYN != 0 { 1 } else { 0 };
                let fin_flag = if hdr.flags & TCP_FIN != 0 { 1 } else { 0 };

                if seg_len > 0 || syn_flag != 0 || fin_flag != 0 {
                    let expected_ack = tcb.rcv_nxt;
                    if hdr.seq == expected_ack {
                        tcb.rcv_nxt = hdr.seq.wrapping_add(seg_len + syn_flag + fin_flag);
                        // Send ACK
                        let ack = OutgoingSegment {
                            flags: TCP_ACK,
                            seq: tcb.snd_nxt,
                            ack: tcb.rcv_nxt,
                            payload: Vec::new(),
                            dst_port: tcb.remote_port,
                        };
                        if fin_flag != 0 {
                            // Passive close: FIN received
                            tcb.state = TcpState::CloseWait;
                            // Send ACK + then FIN (done in poll)
                        }
                        return vec![ack];
                    }
                }
                vec![]
            }
            _ => vec![],
        }
    }

// Re-open impl block for methods that need &mut self
impl TcpManager {
    /// Process a new SYN for a listening port → create TCB, send SYN+ACK.
    fn process_new_syn(
        &mut self,
        key: ConnKey,
        hdr: &TcpHeader,
        now: Instant,
    ) -> Vec<OutgoingSegment> {
        let (local_ip, local_port, remote_ip, remote_port) = key;
        let iss = rand_seq();
        let irs = hdr.seq;
        let rcv_nxt = irs.wrapping_add(1); // consume SYN

        let mut tcb = Tcb::new_server(local_ip, remote_ip, local_port, remote_port);
        tcb.state = TcpState::SynReceived;
        tcb.iss = iss;
        tcb.irs = irs;
        tcb.rcv_nxt = rcv_nxt;
        tcb.snd_una = iss;
        tcb.snd_nxt = iss.wrapping_add(1); // SYN consumes 1 byte in seq space
        tcb.snd_wnd = hdr.window;
        tcb.retransmit_at = Some(now + INITIAL_RTO);
        tcb.rto = INITIAL_RTO;

        println!(
            "TCP: SYN from {}:{} → port {} (iss={}, irs={})",
            ip_str(remote_ip),
            remote_port,
            local_port,
            iss,
            irs,
        );

        self.connections.insert(key, tcb);

        vec![OutgoingSegment {
            flags: TCP_SYN | TCP_ACK,
            seq: iss,
            ack: rcv_nxt,
            payload: Vec::new(),
            dst_port: remote_port,
        }]
    }

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
                    if let Some(ref seg) = tcb.last_sent {
                        let h = parse_tcp(seg).unwrap().0;
                        tcb.retransmit_at = Some(now + tcb.rto);
                        tcb.rto = (tcb.rto * 2).min(MAX_RTO);
                        tcb.retransmit_count += 1;
                        retransmits.push((
                            *key,
                            OutgoingSegment {
                                flags: h.flags,
                                seq: h.seq,
                                ack: if h.flags & TCP_ACK != 0 { tcb.rcv_nxt } else { h.ack },
                                payload: Vec::new(),
                                dst_port: tcb.remote_port,
                            },
                        ));
                    }
                }
            }
        }

        // Remove closed connections
        self.connections.retain(|_, tcb| tcb.state != TcpState::Closed);

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

    /// Record a segment that was just sent (for retransmission tracking).
    pub fn record_sent(&mut self, key: &ConnKey, segment: &[u8], now: Instant) {
        if let Some(tcb) = self.connections.get_mut(key) {
            tcb.last_sent = Some(segment.to_vec());
            if tcb.retransmit_at.is_none() {
                tcb.retransmit_at = Some(now + tcb.rto);
            }
        }
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

fn rand_seq() -> u32 {
    // Simple pseudo-random ISS based on time
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (t & 0xFFFF_FFFF) as u32
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
        let (hdr, payload) = parse_tcp(&header).expect("should parse");
        assert_eq!(hdr.src_port, 8080);
        assert_eq!(hdr.dst_port, 80);
        assert_eq!(hdr.seq, 1000);
        assert_eq!(hdr.ack, 2000);
        assert_eq!(hdr.flags, TCP_SYN | TCP_ACK);
        assert_eq!(hdr.window, 65535);
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
        let (hdr, payload) = parse_tcp(&seg).expect("should parse");
        assert_eq!(hdr.flags, TCP_PSH | TCP_ACK);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn test_syn_creates_connection() {
        let mut mgr = TcpManager::new();
        mgr.listen(8080);
        assert!(mgr.is_listening(8080));

        let (key, outgoing) = mgr.process(
            [10, 0, 0, 2], // local
            [10, 0, 0, 1], // remote
            &TcpHeader {
                src_port: 12345,
                dst_port: 8080,
                seq: 500,
                ack: 0,
                data_offset: 5,
                flags: TCP_SYN,
                window: 65535,
                checksum: 0,
                urgent: 0,
            },
            &[],
            Instant::now(),
        );

        let key = key.expect("should create connection");
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].flags, TCP_SYN | TCP_ACK);

        let tcb = mgr.get(&key).expect("TCB should exist");
        assert_eq!(tcb.state, TcpState::SynReceived);
        assert_eq!(tcb.irs, 500);
        assert_eq!(tcb.rcv_nxt, 501); // consumed SYN
    }

    #[test]
    fn test_handshake_completes() {
        let mut mgr = TcpManager::new();
        mgr.listen(8080);

        let now = Instant::now();

        // 1. Receive SYN
        let (key, outgoing) = mgr.process(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &TcpHeader {
                src_port: 12345,
                dst_port: 8080,
                seq: 500,
                ack: 0,
                data_offset: 5,
                flags: TCP_SYN,
                window: 65535,
                checksum: 0,
                urgent: 0,
            },
            &[],
            now,
        );
        let key = key.expect("connection created");
        assert_eq!(outgoing.len(), 1);
        let syn_ack_seq = outgoing[0].seq;
        let syn_ack_ack = outgoing[0].ack;

        // 2. Receive ACK of our SYN+ACK
        let (_, outgoing) = mgr.process(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &TcpHeader {
                src_port: 12345,
                dst_port: 8080,
                seq: 501,          // ACK of the SYN (+1 from original seq=500)
                ack: syn_ack_seq.wrapping_add(1), // ACK covers our SYN
                data_offset: 5,
                flags: TCP_ACK,
                window: 65535,
                checksum: 0,
                urgent: 0,
            },
            &[],
            now,
        );
        assert!(outgoing.is_empty());

        let tcb = mgr.get(&key).expect("TCB should exist");
        assert_eq!(tcb.state, TcpState::Established);
    }

    #[test]
    fn test_no_listener_sends_rst() {
        let mut mgr = TcpManager::new();
        // No listener on port 8080
        let (key, outgoing) = mgr.process(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &TcpHeader {
                src_port: 12345,
                dst_port: 8080,
                seq: 500,
                ack: 0,
                data_offset: 5,
                flags: TCP_SYN,
                window: 65535,
                checksum: 0,
                urgent: 0,
            },
            &[],
            Instant::now(),
        );
        assert!(key.is_none());
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].flags & TCP_RST, TCP_RST);
    }
}
