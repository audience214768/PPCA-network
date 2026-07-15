//! Socket API — client-side TCP: TcpSocket for connect/send/recv/close.

use crate::tcp::{ConnKey, TcpManager, TcpState, OutgoingSegment};

/// Handle to an established TCP connection.
#[derive(Clone, Copy)]
pub struct TcpSocket {
    pub key: ConnKey,
}

/// Read data from a socket.
pub fn recv(manager: &mut TcpManager, sock: &TcpSocket) -> Vec<u8> {
    manager.drain_data(&sock.key)
}

/// Queue data for sending. Appends to send_buffer, returns OutgoingSegment(s).
pub fn send(manager: &mut TcpManager, sock: &TcpSocket, data: &[u8]) -> Vec<OutgoingSegment> {
    let tcb = match manager.get_mut(&sock.key) {
        Some(t) => t,
        None => return vec![],
    };
    if tcb.state != TcpState::Established {
        return vec![];
    }
    let seq = tcb.snd_nxt;
    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(data.len() as u32);
    // Store data for potential retransmission
    tcb.send_buffer.extend_from_slice(data);
    vec![OutgoingSegment {
        flags: crate::tcp::TCP_PSH | crate::tcp::TCP_ACK,
        seq,
        ack: tcb.rcv_nxt,
        payload: data.to_vec(),
        dst_port: tcb.remote_port,
    }]
}

/// Close a socket (initiate FIN or respond to CloseWait).
pub fn close(manager: &mut TcpManager, sock: &TcpSocket, now: std::time::Instant) -> Vec<OutgoingSegment> {
    manager.close_conn(&sock.key, now)
}

/// Initiate an active connection (client-side SYN). Returns initial SYN segment.
pub fn connect(
    manager: &mut TcpManager,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    remote_port: u16,
    now: std::time::Instant,
) -> (Option<TcpSocket>, Vec<OutgoingSegment>) {
    let (opt_key, segs) = manager.initiate_connect(local_ip, remote_ip, remote_port, now);
    (opt_key.map(|key| TcpSocket { key }), segs)
}
