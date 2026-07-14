//! ARP protocol — packet parsing/construction and address cache (IP→MAC).

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const ARP_HTYPE_ETHER: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_HLEN_ETHER: u8 = 6;
pub const ARP_PLEN_IPV4: u8 = 4;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;
pub const ARP_PKT_LEN: usize = 28; // 8B base + 2×6B HW + 2×4B proto

// Cache TTLs
const CACHE_TTL: Duration = Duration::from_secs(60);
const PENDING_RETRY_INTERVAL: Duration = Duration::from_secs(3);
const MAX_RETRIES: u32 = 3;

#[derive(Debug)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: u16,
    pub sha: [u8; 6], // sender hardware address
    pub spa: [u8; 4], // sender protocol address
    pub tha: [u8; 6], // target hardware address
    pub tpa: [u8; 4], // target protocol address
}

pub fn parse_arp(data: &[u8]) -> Option<ArpPacket> {
    if data.len() < ARP_PKT_LEN {
        return None;
    }
    let mut sha = [0u8; 6];
    let mut spa = [0u8; 4];
    let mut tha = [0u8; 6];
    let mut tpa = [0u8; 4];
    sha.copy_from_slice(&data[8..14]);
    spa.copy_from_slice(&data[14..18]);
    tha.copy_from_slice(&data[18..24]);
    tpa.copy_from_slice(&data[24..28]);
    Some(ArpPacket {
        htype: u16::from_be_bytes([data[0], data[1]]),
        ptype: u16::from_be_bytes([data[2], data[3]]),
        hlen: data[4],
        plen: data[5],
        oper: u16::from_be_bytes([data[6], data[7]]),
        sha,
        spa,
        tha,
        tpa,
    })
}

pub fn build_arp(
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
) -> Vec<u8> {
    let mut buf = vec![0u8; ARP_PKT_LEN];
    buf[0..2].copy_from_slice(&htype.to_be_bytes());
    buf[2..4].copy_from_slice(&ptype.to_be_bytes());
    buf[4] = hlen;
    buf[5] = plen;
    buf[6..8].copy_from_slice(&oper.to_be_bytes());
    buf[8..14].copy_from_slice(&sha);
    buf[14..18].copy_from_slice(&spa);
    buf[18..24].copy_from_slice(&tha);
    buf[24..28].copy_from_slice(&tpa);
    buf
}

pub fn build_arp_reply(
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
) -> Vec<u8> {
    build_arp(
        ARP_HTYPE_ETHER,
        ARP_PTYPE_IPV4,
        ARP_HLEN_ETHER,
        ARP_PLEN_IPV4,
        ARP_OP_REPLY,
        sha,
        spa,
        tha,
        tpa,
    )
}

pub fn build_arp_request(sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
    build_arp(
        ARP_HTYPE_ETHER,
        ARP_PTYPE_IPV4,
        ARP_HLEN_ETHER,
        ARP_PLEN_IPV4,
        ARP_OP_REQUEST,
        sha,
        spa,
        [0u8; 6],
        tpa,
    )
}

struct CacheEntry {
    mac: [u8; 6],
    expires: Instant,
}

struct PendingEntry {
    packets: Vec<Vec<u8>>,
    last_request: Instant,
    retries: u32,
}

pub struct ArpCache {
    entries: HashMap<[u8; 4], CacheEntry>,
    pending: HashMap<[u8; 4], PendingEntry>,
}

/// Result of a tick — which IPs need an ARP request (re)sent, and which timed out.
pub struct TickResult {
    pub retry_ips: Vec<[u8; 4]>,
    pub timed_out_ips: Vec<[u8; 4]>,
}

impl ArpCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Look up MAC address for an IP. Returns None if not found or expired.
    pub fn lookup(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        let entry = self.entries.get(&ip)?;
        if entry.expires < Instant::now() {
            return None;
        }
        Some(entry.mac)
    }

    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) -> Vec<Vec<u8>> {
        self.entries.insert(
            ip,
            CacheEntry {
                mac,
                expires: Instant::now() + CACHE_TTL,
            },
        );
        self.pending.remove(&ip).map(|p| p.packets).unwrap_or_default()
    }

    /// Soft-update: learn MAC from any ARP packet without draining pending.
    pub fn learn(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        if ip == [0u8; 4] || mac == [0u8; 6] {
            return;
        }
        self.entries.insert(
            ip,
            CacheEntry {
                mac,
                expires: Instant::now() + CACHE_TTL,
            },
        );
    }

    /// Check if we need to send an ARP request for this IP (no cache, no pending).
    pub fn needs_resolution(&self, ip: [u8; 4]) -> bool {
        self.lookup(ip).is_none() && !self.pending.contains_key(&ip)
    }

    /// Queue an IP packet waiting for ARP resolution.
    /// Returns true if this is the first packet for this IP (caller should send ARP request).
    pub fn queue_packet(&mut self, ip: [u8; 4], packet: Vec<u8>, now: Instant) -> bool {
        let is_new = !self.pending.contains_key(&ip);
        let entry = self.pending.entry(ip).or_insert_with(|| PendingEntry {
            packets: Vec::new(),
            last_request: now,
            retries: 0,
        });
        entry.packets.push(packet);
        is_new
    }

    pub fn tick(&mut self, now: Instant) -> TickResult {
        let mut retry_ips = Vec::new();
        let mut timed_out_ips = Vec::new();

        for (&ip, entry) in &mut self.pending {
            if entry.retries >= MAX_RETRIES {
                if now.duration_since(entry.last_request) >= PENDING_RETRY_INTERVAL {
                    timed_out_ips.push(ip);
                }
            } else if entry.last_request + PENDING_RETRY_INTERVAL <= now {
                retry_ips.push(ip);
            }
        }

        for ip in &timed_out_ips {
            self.pending.remove(ip);
        }

        TickResult {
            retry_ips,
            timed_out_ips,
        }
    }

    pub fn record_request(&mut self, ip: [u8; 4], now: Instant) {
        if let Some(entry) = self.pending.get_mut(&ip) {
            entry.last_request = now;
            entry.retries += 1;
        } else {
            self.pending.insert(
                ip,
                PendingEntry {
                    packets: Vec::new(),
                    last_request: now,
                    retries: 1,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_roundtrip() {
        let pkt = build_arp(
            ARP_HTYPE_ETHER,
            ARP_PTYPE_IPV4,
            ARP_HLEN_ETHER,
            ARP_PLEN_IPV4,
            ARP_OP_REQUEST,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            [10, 0, 0, 1],
            [0u8; 6],
            [10, 0, 0, 2],
        );
        let parsed = parse_arp(&pkt).expect("should parse");
        assert_eq!(parsed.htype, ARP_HTYPE_ETHER);
        assert_eq!(parsed.ptype, ARP_PTYPE_IPV4);
        assert_eq!(parsed.oper, ARP_OP_REQUEST);
        assert_eq!(parsed.sha, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(parsed.spa, [10, 0, 0, 1]);
        assert_eq!(parsed.tpa, [10, 0, 0, 2]);
    }

    #[test]
    fn test_cache_insert_lookup() {
        let mut cache = ArpCache::new();
        let ip = [10, 0, 0, 1];
        let mac = [0xaa; 6];

        cache.learn(ip, mac);
        assert_eq!(cache.lookup(ip), Some(mac));
        assert_eq!(cache.lookup([10, 0, 0, 2]), None);
    }

    #[test]
    fn test_cache_drain_pending() {
        let mut cache = ArpCache::new();
        let ip = [10, 0, 0, 1];
        let mac = [0xaa; 6];
        let now = Instant::now();

        cache.queue_packet(ip, vec![1, 2, 3], now);
        cache.queue_packet(ip, vec![4, 5, 6], now);

        let drained = cache.insert(ip, mac);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0], vec![1, 2, 3]);
        assert_eq!(drained[1], vec![4, 5, 6]);
        assert!(cache.pending.is_empty());
    }

    #[test]
    fn test_needs_resolution() {
        let cache = ArpCache::new();
        assert!(cache.needs_resolution([10, 0, 0, 1]));
        assert!(cache.lookup([10, 0, 0, 1]).is_none());
    }

    #[test]
    fn test_build_reply() {
        let reply = build_arp_reply(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [10, 0, 0, 2],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            [10, 0, 0, 1],
        );
        let parsed = parse_arp(&reply).expect("should parse");
        assert_eq!(parsed.oper, ARP_OP_REPLY);
        assert_eq!(parsed.sha, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(parsed.spa, [10, 0, 0, 2]);
        assert_eq!(parsed.tha, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(parsed.tpa, [10, 0, 0, 1]);
    }

    #[test]
    fn test_pending_retry() {
        let mut cache = ArpCache::new();
        let ip = [10, 0, 0, 99];
        let now = Instant::now();

        // First queue — should be new
        let is_new = cache.queue_packet(ip, vec![1], now);
        assert!(is_new);

        // Immediately — no retry needed
        let result = cache.tick(now);
        assert!(result.retry_ips.is_empty());

        // Record first request
        cache.record_request(ip, now);

        // After 3s — should need retry
        let later = now + Duration::from_secs(4);
        let result = cache.tick(later);
        assert_eq!(result.retry_ips, vec![ip]);

        // After max retries (3) and 3 more seconds — should time out
        cache.record_request(ip, later);       // retry 2
        cache.record_request(ip, later);       // retry 3
        cache.record_request(ip, later);       // retry 4 (MAX_RETRIES=3, so this is the 4th call!)
                                              // Actually the check is >= MAX_RETRIES, so after 3 we wait
        let timeout = later + Duration::from_secs(4);
        let result = cache.tick(timeout);
        assert_eq!(result.timed_out_ips, vec![ip]);
    }

    #[test]
    fn test_pending_second_packet_not_new() {
        let mut cache = ArpCache::new();
        let ip = [10, 0, 0, 1];
        let now = Instant::now();

        let is_new = cache.queue_packet(ip, vec![1], now);
        assert!(is_new);

        let is_new = cache.queue_packet(ip, vec![2], now);
        assert!(!is_new);
    }
}
