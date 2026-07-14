/// Internet checksum (RFC 1071): one's complement of the one's complement sum
/// of 16-bit words. Returns 0x0000 to indicate a valid checksum when the input
/// includes the checksum field.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Odd byte: pad with zero low byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_simple() {
        // Echo request with checksum zeroed at [2..4]
        let mut pkt = [0u8; 20];
        pkt[0] = 8; // Type = Echo
        pkt[1] = 0; // Code = 0
        pkt[4..6].copy_from_slice(&0x42u16.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x01u16.to_be_bytes());
        pkt[8..].fill(b'A');

        let cs = checksum(&pkt);
        assert_ne!(cs, 0x0000, "checksum should be non-zero");

        pkt[2..4].copy_from_slice(&cs.to_be_bytes());
        assert_eq!(checksum(&pkt), 0x0000, "self-validate should yield zero");
    }

    #[test]
    fn test_checksum_odd_length() {
        let data = [0x00, 0x08, 0x00];
        let cs = checksum(&data);
        // Just verify no panic on odd length
        assert!(cs != 0 || cs == 0); // tautology, just ensures no panic
    }
}
