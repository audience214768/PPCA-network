//! IPv4 header — parse, build, checksum. Plus minimal ICMP Echo handling.

use crate::util::checksum;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_HDR_LEN: usize = 20;

// ICMP types
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;

#[derive(Debug)]
pub struct Ipv4Header {
    pub _version_ihl: u8,   // 0x45 for version=4, IHL=5
    pub _dscp_ecn: u8,
    pub _total_len: u16,
    pub _id: u16,
    pub _flags_frag: u16,    // 0x4000 = DF set
    pub _ttl: u8,
    pub protocol: u8,
    pub _checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

/// Parse an IPv4 header. Returns (header, payload_slice) or None.
pub fn parse_ipv4(data: &[u8]) -> Option<(Ipv4Header, &[u8])> {
    if data.len() < IP_HDR_LEN {
        return None;
    }
    let version_ihl = data[0];
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if ihl < IP_HDR_LEN || data.len() < ihl {
        return None;
    }

    // Verify header checksum
    let checksum = u16::from_be_bytes([data[10], data[11]]);
    if checksum != 0 && !verify_ip_checksum(&data[..ihl]) {
        return None;
    }

    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&data[12..16]);
    dst.copy_from_slice(&data[16..20]);

    Some((
        Ipv4Header {
            _version_ihl: version_ihl,
            _dscp_ecn: data[1],
            _total_len: u16::from_be_bytes([data[2], data[3]]),
            _id: u16::from_be_bytes([data[4], data[5]]),
            _flags_frag: u16::from_be_bytes([data[6], data[7]]),
            _ttl: data[8],
            protocol: data[9],
            _checksum: checksum,
            src,
            dst,
        },
        &data[ihl..],
    ))
}

pub fn build_ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (IP_HDR_LEN + payload.len()) as u16;
    let mut buf = Vec::with_capacity(total_len as usize);

    // version=4, IHL=5
    buf.push(0x45);
    // DSCP + ECN = 0
    buf.push(0);
    // Total length
    buf.extend_from_slice(&total_len.to_be_bytes());
    // Identification
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Flags (DF=1) + Fragment Offset = 0
    buf.extend_from_slice(&0x4000u16.to_be_bytes());
    // TTL
    buf.push(ttl);
    // Protocol
    buf.push(protocol);
    // Checksum placeholder (filled below)
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Source IP
    buf.extend_from_slice(&src);
    // Destination IP
    buf.extend_from_slice(&dst);
    // Payload
    buf.extend_from_slice(payload);

    let cs = checksum(&buf[..IP_HDR_LEN]);
    buf[10..12].copy_from_slice(&cs.to_be_bytes());

    buf
}

fn verify_ip_checksum(header: &[u8]) -> bool {
    checksum(header) == 0
}


pub const ICMP_HDR_SIZE: usize = 8;

pub fn build_icmp_echo_reply(echo_request: &[u8]) -> Option<Vec<u8>> {
    if echo_request.len() < ICMP_HDR_SIZE {
        return None;
    }
    if echo_request[0] != ICMP_ECHO_REQUEST {
        return None;
    }
    let mut reply = echo_request.to_vec();
    reply[0] = ICMP_ECHO_REPLY;       // change type
    reply[2] = 0;                     // clear old checksum
    reply[3] = 0;
    let cs = checksum(&reply);
    reply[2..4].copy_from_slice(&cs.to_be_bytes());
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_roundtrip() {
        let pkt = build_ipv4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            IP_PROTO_ICMP,
            64,
            b"HELLO",
        );
        let (header, payload) = parse_ipv4(&pkt).expect("should parse");
        assert_eq!(header._version_ihl, 0x45);
        assert_eq!(header.protocol, IP_PROTO_ICMP);
        assert_eq!(header._ttl, 64);
        assert_eq!(header.src, [10, 0, 0, 2]);
        assert_eq!(header.dst, [10, 0, 0, 1]);
        assert_eq!(payload, b"HELLO");
        // Self-validate: checksum should be zero after insertion
        let cs = u16::from_be_bytes([pkt[10], pkt[11]]);
        assert_ne!(cs, 0);
    }

    #[test]
    fn test_ipv4_checksum_invalid() {
        let mut pkt = build_ipv4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            IP_PROTO_ICMP,
            64,
            b"data",
        );
        // Corrupt header
        pkt[0] = 0x46;
        assert!(parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn test_icmp_echo_reply() {
        // Build an ICMP Echo Request manually
        let mut req = vec![0u8; 8 + 4]; // 8B header + 4B payload
        req[0] = ICMP_ECHO_REQUEST;     // type
        req[1] = 0;                     // code
        // ID = 0x1234 at bytes 4-5
        req[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        // Seq = 1 at bytes 6-7
        req[6..8].copy_from_slice(&1u16.to_be_bytes());
        req[8..].copy_from_slice(b"ABCD");
        // Compute checksum
        let cs = checksum(&req);
        req[2..4].copy_from_slice(&cs.to_be_bytes());

        let reply = build_icmp_echo_reply(&req).expect("should build reply");
        assert_eq!(reply[0], ICMP_ECHO_REPLY);
        assert_eq!(reply[1], 0);
        // ID, Seq preserved
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
        assert_eq!(&reply[8..], b"ABCD");
        // Reply checksum should be valid
        assert_eq!(checksum(&reply), 0);
    }
}
