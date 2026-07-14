//! ICMP packet construction, parsing, and checksum.
//!
//! Reuses checksum and echo request/reply logic from ping, with
//! additional ICMP error message parsing for traceroute.

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_HEADER_SIZE: usize = 8;

/// Build an ICMP Echo Request packet (Type=8, Code=0).
pub fn build_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let len = ICMP_HEADER_SIZE + payload.len();
    let mut buf = vec![0u8; len];

    buf[0] = ICMP_ECHO_REQUEST;
    buf[1] = 0; // Code
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..].copy_from_slice(payload);

    let cs = checksum(&buf);
    buf[2..4].copy_from_slice(&cs.to_be_bytes());

    buf
}

/// Parse an ICMP Echo Reply. Returns (id, seq, payload).
pub fn parse_echo_reply(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    if data.len() < ICMP_HEADER_SIZE {
        return None;
    }
    if data[0] != ICMP_ECHO_REPLY {
        return None;
    }
    let id = u16::from_be_bytes([data[4], data[5]]);
    let seq = u16::from_be_bytes([data[6], data[7]]);
    let payload = &data[ICMP_HEADER_SIZE..];
    Some((id, seq, payload))
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

pub fn parse_icmp_error(icmp_body: &[u8]) -> Option<(u8, u8, u8, [u8; 8])> {
    if icmp_body.len() < 8 + 20 + 8 {
        return None;
    }

    let icmp_type = icmp_body[0];
    let icmp_code = icmp_body[1];
    if icmp_type != ICMP_TIME_EXCEEDED && icmp_type != ICMP_DEST_UNREACH {
        return None;
    }

    let inner_ip = &icmp_body[8..];
    let inner_ihl = (inner_ip[0] & 0x0F) as usize * 4;
    let protocol = inner_ip[9];

    if inner_ip.len() < inner_ihl + 8 {
        return None;
    }

    let transport: [u8; 8] = inner_ip[inner_ihl..inner_ihl + 8].try_into().unwrap();
    Some((icmp_type, icmp_code, protocol, transport))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_self_validating() {
        let mut pkt = [0u8; 20];
        pkt[0] = 8; // Type = Echo
        pkt[1] = 0; // Code = 0
        pkt[4..6].copy_from_slice(&0x42u16.to_be_bytes()); // ID
        pkt[6..8].copy_from_slice(&0x01u16.to_be_bytes()); // Seq
        pkt[8..].fill(b'A');

        let cs = checksum(&pkt);
        assert_ne!(cs, 0x0000);

        pkt[2..4].copy_from_slice(&cs.to_be_bytes());
        assert_eq!(checksum(&pkt), 0x0000);
    }

    #[test]
    fn test_build_and_parse() {
        let payload = b"HELLO_WORLD";
        let pkt = build_echo_request(0x1234, 0x0001, payload);

        assert_eq!(checksum(&pkt), 0x0000);

        let mut reply = pkt.clone();
        reply[0] = ICMP_ECHO_REPLY;
        reply[2] = 0;
        reply[3] = 0;
        let cs = checksum(&reply);
        reply[2..4].copy_from_slice(&cs.to_be_bytes());

        let (id, seq, pld) = parse_echo_reply(&reply).expect("should parse");
        assert_eq!(id, 0x1234);
        assert_eq!(seq, 0x0001);
        assert_eq!(pld, payload);
    }

    #[test]
    fn test_parse_icmp_error_rejects_echo() {
        // An Echo Reply (type 0) should not parse as an error
        let mut pkt = [0u8; 60];
        pkt[0] = ICMP_ECHO_REPLY;
        assert!(parse_icmp_error(&pkt).is_none());
    }

    #[test]
    fn test_parse_icmp_error_extracts_udp() {
        // Build a minimal ICMP Time Exceeded message with inner UDP packet
        let mut buf = vec![0u8; 8 + 20 + 8]; // ICMP hdr + inner IP + 8B UDP
        buf[0] = ICMP_TIME_EXCEEDED; // outer ICMP type
        buf[1] = 0; // code

        // Inner IP header (minimal 20 bytes)
        buf[8] = 0x45; // Version=4, IHL=5
        buf[8 + 9] = 17; // Protocol = UDP

        // Inner UDP header (8 bytes at offset 8 + 20 = 28)
        buf[28..30].copy_from_slice(&0x1234u16.to_be_bytes()); // src_port
        buf[30..32].copy_from_slice(&0x82A2u16.to_be_bytes()); // dst_port = 33442
        buf[32..34].copy_from_slice(&0x0028u16.to_be_bytes()); // length
        buf[34..36].copy_from_slice(&0x0000u16.to_be_bytes()); // checksum

        let (icmp_type, icmp_code, protocol, transport) =
            parse_icmp_error(&buf).expect("should parse");

        assert_eq!(icmp_type, ICMP_TIME_EXCEEDED);
        assert_eq!(icmp_code, 0);
        assert_eq!(protocol, 17); // UDP

        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
        assert_eq!(dst_port, 33442);
    }
}
