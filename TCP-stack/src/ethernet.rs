//! Ethernet II frame — parse and construct.

pub const ETH_HDR_LEN: usize = 14;
pub const ETH_TYPE_IPV4: u16 = 0x0800;
pub const ETH_TYPE_ARP: u16 = 0x0806;
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// Returns None if too short. Returns (header fields, payload slice).
pub fn parse_frame(data: &[u8]) -> Option<(EthernetHdr, &[u8])> {
    if data.len() < ETH_HDR_LEN {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&data[0..6]);
    src.copy_from_slice(&data[6..12]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    Some((
        EthernetHdr {
            dst,
            src,
            ethertype,
        },
        &data[ETH_HDR_LEN..],
    ))
}

pub fn build_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ETH_HDR_LEN + payload.len());
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&ethertype.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[derive(Debug)]
pub struct EthernetHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_roundtrip() {
        let payload = b"hello world";
        let frame = build_frame([0x01; 6], [0x02; 6], ETH_TYPE_IPV4, payload);
        let (hdr, pld) = parse_frame(&frame).expect("should parse");
        assert_eq!(hdr.dst, [0x01; 6]);
        assert_eq!(hdr.src, [0x02; 6]);
        assert_eq!(hdr.ethertype, ETH_TYPE_IPV4);
        assert_eq!(pld, payload);
    }

    #[test]
    fn test_parse_too_short() {
        assert!(parse_frame(&[0u8; 10]).is_none());
    }
}
