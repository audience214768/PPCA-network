//! DNS wire format encoder / decoder (RFC 1035).
//!
//! Name compression is implemented for *decoding* (following pointers in
//! upstream responses). Our *encoding* currently uses uncompressed names;
//! a working compression encoder is kept below for future optimization.

use std::collections::{HashMap, HashSet};
use std::fmt;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_MX: u16 = 15;
pub const TYPE_AAAA: u16 = 28;

pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

const FLAG_QR: u16 = 0x8000;
#[allow(dead_code)]
const FLAG_RA: u16 = 0x0080;

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    #[allow(dead_code)]
    pub fn is_response(&self) -> bool { self.flags & FLAG_QR != 0 }
    pub fn rcode(&self) -> u8 { (self.flags & 0x000F) as u8 }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion { pub qname: String, pub qtype: u16, pub qclass: u16 }

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A([u8; 4]),
    AAAA([u8; 16]),
    NS(String),
    CNAME(String),
    MX { preference: u16, exchange: String },
    SOA { mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct DnsRR { pub name: String, pub rtype: u16, pub class: u16, pub ttl: u32, pub rdata: RData }

#[derive(Debug, Clone)]
pub struct DnsMessage { pub header: DnsHeader, pub questions: Vec<DnsQuestion>, pub answers: Vec<DnsRR>, pub authorities: Vec<DnsRR>, pub additionals: Vec<DnsRR> }

// --- Name codec (decode handles compression pointers; encode is vanilla) ---

pub fn encode_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() { continue; }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
}

pub fn decode_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut jump_end = start;
    let mut visited = HashSet::new();
    loop {
        if offset >= msg.len() { return None; }
        let len = msg[offset];
        if len == 0 { offset += 1; break; }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= msg.len() { return None; }
            let ptr = u16::from_be_bytes([msg[offset], msg[offset + 1]]) & 0x3FFF;
            if !visited.insert(ptr as usize) { return None; }
            if !jumped { jump_end = offset + 2; jumped = true; }
            offset = ptr as usize;
            continue;
        }
        let label_len = len as usize;
        if offset + 1 + label_len > msg.len() { return None; }
        labels.push(std::str::from_utf8(&msg[offset + 1..offset + 1 + label_len]).ok()?.to_ascii_lowercase());
        offset += 1 + label_len;
    }
    let name = if labels.is_empty() { ".".into() } else { labels.join(".") + "." };
    let consumed = if jumped { jump_end } else { offset };
    Some((name, consumed))
}

// --- Header ---

pub fn encode_header(h: &DnsHeader) -> Vec<u8> {
    let mut b = Vec::with_capacity(12);
    b.extend_from_slice(&h.id.to_be_bytes());
    b.extend_from_slice(&h.flags.to_be_bytes());
    b.extend_from_slice(&h.qdcount.to_be_bytes());
    b.extend_from_slice(&h.ancount.to_be_bytes());
    b.extend_from_slice(&h.nscount.to_be_bytes());
    b.extend_from_slice(&h.arcount.to_be_bytes());
    b
}

pub fn decode_header(msg: &[u8]) -> Option<DnsHeader> {
    if msg.len() < 12 { return None; }
    Some(DnsHeader {
        id: u16::from_be_bytes([msg[0], msg[1]]),
        flags: u16::from_be_bytes([msg[2], msg[3]]),
        qdcount: u16::from_be_bytes([msg[4], msg[5]]),
        ancount: u16::from_be_bytes([msg[6], msg[7]]),
        nscount: u16::from_be_bytes([msg[8], msg[9]]),
        arcount: u16::from_be_bytes([msg[10], msg[11]]),
    })
}

// --- Question ---

pub fn decode_question(msg: &[u8], offset: usize) -> Option<(DnsQuestion, usize)> {
    let (qname, off) = decode_name(msg, offset)?;
    if off + 4 > msg.len() { return None; }
    Some((DnsQuestion { qname, qtype: u16::from_be_bytes([msg[off], msg[off+1]]), qclass: u16::from_be_bytes([msg[off+2], msg[off+3]]) }, off + 4))
}

pub fn encode_question(q: &DnsQuestion) -> Vec<u8> {
    let mut b = encode_name(&q.qname);
    b.extend_from_slice(&q.qtype.to_be_bytes());
    b.extend_from_slice(&q.qclass.to_be_bytes());
    b
}

// --- RR ---

pub fn encode_rr(rr: &DnsRR) -> Vec<u8> {
    let mut b = encode_name(&rr.name);
    b.extend_from_slice(&rr.rtype.to_be_bytes());
    b.extend_from_slice(&rr.class.to_be_bytes());
    b.extend_from_slice(&rr.ttl.to_be_bytes());
    let rdata = encode_rdata(&rr.rdata);
    b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    b.extend_from_slice(&rdata);
    b
}

fn encode_rdata(rdata: &RData) -> Vec<u8> {
    match rdata {
        RData::A(ip) => ip.to_vec(),
        RData::AAAA(ip) => ip.to_vec(),
        RData::NS(n) | RData::CNAME(n) => encode_name(n),
        RData::MX { preference, exchange } => {
            let mut b = vec![];
            b.extend_from_slice(&preference.to_be_bytes());
            b.extend_from_slice(&encode_name(exchange));
            b
        }
        RData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
            let mut b = vec![];
            b.extend_from_slice(&encode_name(mname));
            b.extend_from_slice(&encode_name(rname));
            b.extend_from_slice(&serial.to_be_bytes());
            b.extend_from_slice(&refresh.to_be_bytes());
            b.extend_from_slice(&retry.to_be_bytes());
            b.extend_from_slice(&expire.to_be_bytes());
            b.extend_from_slice(&minimum.to_be_bytes());
            b
        }
        RData::Unknown(d) => d.clone(),
    }
}

pub fn decode_rr(msg: &[u8], offset: usize) -> Option<(DnsRR, usize)> {
    let (name, off) = decode_name(msg, offset)?;
    if off + 10 > msg.len() { return None; }
    let rtype = u16::from_be_bytes([msg[off], msg[off+1]]);
    let class = u16::from_be_bytes([msg[off+2], msg[off+3]]);
    let ttl = u32::from_be_bytes([msg[off+4], msg[off+5], msg[off+6], msg[off+7]]);
    let rdlength = u16::from_be_bytes([msg[off+8], msg[off+9]]) as usize;
    let rd_start = off + 10;
    if rd_start + rdlength > msg.len() { return None; }
    Some((DnsRR { name, rtype, class, ttl, rdata: decode_rdata(msg, rtype, rd_start, rdlength)? }, rd_start + rdlength))
}

fn decode_rdata(msg: &[u8], rtype: u16, start: usize, len: usize) -> Option<RData> {
    let s = &msg[start..start+len];
    match rtype {
        TYPE_A => { if len < 4 { None } else { let mut ip=[0u8;4]; ip.copy_from_slice(&s[..4]); Some(RData::A(ip)) } }
        TYPE_AAAA => { if len < 16 { None } else { let mut ip=[0u8;16]; ip.copy_from_slice(&s[..16]); Some(RData::AAAA(ip)) } }
        TYPE_NS => { let (n,_) = decode_name(msg, start)?; Some(RData::NS(n)) }
        TYPE_CNAME => { let (n,_) = decode_name(msg, start)?; Some(RData::CNAME(n)) }
        TYPE_MX => {
            if len < 3 { return None; }
            Some(RData::MX { preference: u16::from_be_bytes([s[0], s[1]]), exchange: decode_name(msg, start+2)?.0 })
        }
        TYPE_SOA => {
            let (mname, o1) = decode_name(msg, start)?;
            let (rname, o2) = decode_name(msg, o1)?;
            if o2 + 20 > start + len { return None; }
            Some(RData::SOA {
                mname, rname,
                serial:   u32::from_be_bytes([msg[o2], msg[o2+1], msg[o2+2], msg[o2+3]]),
                refresh:  u32::from_be_bytes([msg[o2+4], msg[o2+5], msg[o2+6], msg[o2+7]]),
                retry:    u32::from_be_bytes([msg[o2+8], msg[o2+9], msg[o2+10], msg[o2+11]]),
                expire:   u32::from_be_bytes([msg[o2+12], msg[o2+13], msg[o2+14], msg[o2+15]]),
                minimum:  u32::from_be_bytes([msg[o2+16], msg[o2+17], msg[o2+18], msg[o2+19]]),
            })
        }
        _ => Some(RData::Unknown(s.to_vec())),
    }
}

// --- Full message ---

pub fn decode_message(msg: &[u8]) -> Option<DnsMessage> {
    let header = decode_header(msg)?;
    let mut off = 12;
    let mut questions = Vec::new();
    for _ in 0..header.qdcount { let (q,o) = decode_question(msg, off)?; questions.push(q); off = o; }
    let mut answers = Vec::new();
    for _ in 0..header.ancount { let (rr,o) = decode_rr(msg, off)?; answers.push(rr); off = o; }
    let mut authorities = Vec::new();
    for _ in 0..header.nscount { let (rr,o) = decode_rr(msg, off)?; authorities.push(rr); off = o; }
    let mut additionals = Vec::new();
    for _ in 0..header.arcount { let (rr,o) = decode_rr(msg, off)?; additionals.push(rr); off = o; }
    Some(DnsMessage { header, questions, answers, authorities, additionals })
}

pub fn encode_message(msg: &DnsMessage) -> Vec<u8> {
    let mut b = encode_header(&msg.header);
    for q in &msg.questions { b.extend_from_slice(&encode_question(q)); }
    for rr in &msg.answers { b.extend_from_slice(&encode_rr(rr)); }
    for rr in &msg.authorities { b.extend_from_slice(&encode_rr(rr)); }
    for rr in &msg.additionals { b.extend_from_slice(&encode_rr(rr)); }
    b
}

// --- Compression (kept for future optimization) ---

#[allow(dead_code)]
fn encode_name_compressed(name: &str, name_map: &mut HashMap<String, usize>, offset: usize) -> Vec<u8> {
    let key = name.to_ascii_lowercase();
    if let Some(&ptr) = name_map.get(&key) {
        let mut b = Vec::with_capacity(2);
        b.extend_from_slice(&(0xC000 | ptr).to_be_bytes());
        return b;
    }
    let buf = encode_name(name);
    let labels: Vec<&str> = key.trim_end_matches('.').split('.').collect();
    name_map.entry(key.clone()).or_insert(offset);
    let mut byte_off = 0usize;
    for i in 0..labels.len().saturating_sub(1) {
        byte_off += 1 + labels[i].len();
        name_map.entry(labels[i + 1..].join(".") + ".").or_insert(offset + byte_off);
    }
    name_map.entry(".".into()).or_insert(offset + buf.len() - 1);
    buf
}

// --- Display ---

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            RData::AAAA(_) => write!(f, "::"),
            RData::NS(n) | RData::CNAME(n) => write!(f, "{n}"),
            RData::MX { preference, exchange } => write!(f, "{preference} {exchange}"),
            RData::SOA { mname, rname, .. } => write!(f, "{mname} {rname}"),
            RData::Unknown(d) => write!(f, "<{} bytes>", d.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_roundtrip() {
        let name = "www.example.com.";
        let encoded = encode_name(name);
        let (decoded, consumed) = decode_name(&encoded, 0).expect("should decode");
        assert_eq!(name, decoded);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_name_pointer() {
        let n1 = encode_name("www.example.com.");
        let mut buf = Vec::new();
        buf.extend_from_slice(&n1);
        buf.push((0xC0 | (4u16 >> 8)) as u8);
        buf.push(4u8);
        let (name, consumed) = decode_name(&buf, n1.len()).expect("should decode");
        assert_eq!(name, "example.com.");
        assert_eq!(consumed, n1.len() + 2);
    }

    #[test]
    fn test_header_roundtrip() {
        let h = DnsHeader { id: 0x1234, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 };
        let enc = encode_header(&h);
        let dec = decode_header(&enc).unwrap();
        assert_eq!(dec.id, 0x1234);
        assert_eq!(dec.flags, 0x8180);
        assert_eq!(dec.qdcount, 1);
    }

    #[test]
    fn test_decode_question() {
        let mut buf = encode_name("example.com.");
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        let (q, consumed) = decode_question(&buf, 0).unwrap();
        assert_eq!(q.qname, "example.com.");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_decode_rr_a() {
        let mut buf = encode_name("example.com.");
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[93, 184, 216, 34]);
        let (rr, consumed) = decode_rr(&buf, 0).unwrap();
        assert_eq!(rr.name, "example.com.");
        assert_eq!(rr.rtype, TYPE_A);
        assert_eq!(rr.ttl, 300);
        assert!(matches!(rr.rdata, RData::A([93, 184, 216, 34])));
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_full_message() {
        let mut qbuf = Vec::new();
        qbuf.extend_from_slice(&0x1234u16.to_be_bytes());
        qbuf.extend_from_slice(&0x0100u16.to_be_bytes());
        qbuf.extend_from_slice(&1u16.to_be_bytes());
        qbuf.extend_from_slice(&0u16.to_be_bytes());
        qbuf.extend_from_slice(&0u16.to_be_bytes());
        qbuf.extend_from_slice(&0u16.to_be_bytes());
        let qname = encode_name("example.com.");
        qbuf.extend_from_slice(&qname);
        qbuf.extend_from_slice(&TYPE_A.to_be_bytes());
        qbuf.extend_from_slice(&CLASS_IN.to_be_bytes());
        let msg = decode_message(&qbuf).unwrap();
        assert_eq!(msg.header.id, 0x1234);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].qname, "example.com.");
    }

    #[test]
    fn test_encode_response() {
        let msg = DnsMessage {
            header: DnsHeader { id: 0x1234, flags: FLAG_QR | FLAG_RA, qdcount: 1, ancount: 1, nscount: 0, arcount: 0 },
            questions: vec![DnsQuestion { qname: "example.com.".into(), qtype: TYPE_A, qclass: CLASS_IN }],
            answers: vec![DnsRR { name: "example.com.".into(), rtype: TYPE_A, class: CLASS_IN, ttl: 300, rdata: RData::A([93,184,216,34]) }],
            authorities: vec![],
            additionals: vec![],
        };
        let wire = encode_message(&msg);
        let decoded = decode_message(&wire).unwrap();
        assert_eq!(decoded.header.id, 0x1234);
        assert!(decoded.header.is_response());
        assert_eq!(decoded.answers.len(), 1);
    }

    #[test]
    fn test_two_a_records() {
        let msg = DnsMessage {
            header: DnsHeader { id: 1, flags: FLAG_QR | FLAG_RA, qdcount: 1, ancount: 2, nscount: 0, arcount: 0 },
            questions: vec![DnsQuestion { qname: "example.com.".into(), qtype: TYPE_A, qclass: CLASS_IN }],
            answers: vec![
                DnsRR { name: "example.com.".into(), rtype: TYPE_A, class: CLASS_IN, ttl: 300, rdata: RData::A([1,2,3,4]) },
                DnsRR { name: "example.com.".into(), rtype: TYPE_A, class: CLASS_IN, ttl: 300, rdata: RData::A([5,6,7,8]) },
            ],
            authorities: vec![],
            additionals: vec![],
        };
        let wire = encode_message(&msg);
        let decoded = decode_message(&wire).unwrap();
        assert_eq!(decoded.answers.len(), 2);
    }
}
