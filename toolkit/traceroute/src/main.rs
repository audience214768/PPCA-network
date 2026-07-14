mod config;
mod icmp;

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process;
use std::time::{Duration, Instant};

use clap::Parser;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use config::Config;
use icmp::{build_echo_request, parse_echo_reply, parse_icmp_error};
use icmp::{ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED};

const BASE_PORT: u16 = 33434;
const PROBE_PAYLOAD_SIZE: usize = 32;

struct Probe {
    ttl: u8,
    /// UDP mode: destination port.  ICMP mode: sequence number.
    marker: u16,
    sent_at: Instant,
    received: bool,
    rtt_ms: f64,
}

fn main() {
    let config = Config::parse();

    let target = match resolve_host(&config.host) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("traceroute: {}: {}", config.host, e);
            process::exit(2);
        }
    };
    let resolved_ip = target.ip().to_string();

    println!(
        "traceroute to {} ({}), {} hops max, {} byte packets",
        config.host, resolved_ip, config.max_hops, PROBE_PAYLOAD_SIZE + 8 + 20
    );

    if config.icmp_mode {
        if let Err(e) = run_icmp(&config, target) {
            eprintln!("traceroute: {e}");
            process::exit(1);
        }
    } else {
        if let Err(e) = run_udp(&config, target) {
            eprintln!("traceroute: {e}");
            process::exit(1);
        }
    }
}

fn run_udp(config: &Config, target: SocketAddr) -> io::Result<()> {
    let recv_sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::ICMPV4),
    )
    .map_err(|e| {
        eprintln!("traceroute: failed to create raw ICMP socket: {e}");
        eprintln!("(try running with sudo)");
        io::Error::new(io::ErrorKind::PermissionDenied, "raw socket failed")
    })?;
    recv_sock.set_read_timeout(Some(Duration::from_millis(100)))?;

    let send_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    let payload = [0u8; PROBE_PAYLOAD_SIZE];

    let num_hops = (config.max_hops - config.first_ttl + 1) as usize;
    let total = num_hops * config.nqueries as usize;
    let mut probes: Vec<Probe> = Vec::with_capacity(total);
    let mut hop_addrs: Vec<Option<IpAddr>> = vec![None; (config.max_hops + 1) as usize];
    let mut target_reached_at: Option<u8> = None;

    let mut port = BASE_PORT;
    for ttl in config.first_ttl..=config.max_hops {
        send_sock.set_ttl_v4(ttl as u32)?;
        for _ in 0..config.nqueries {
            let dest = SocketAddr::new(target.ip(), port);
            let sent_at = Instant::now();
            send_sock.send_to(&payload, &SockAddr::from(dest)).ok();
            probes.push(Probe { ttl, marker: port, sent_at, received: false, rtt_ms: 0.0 });
            port += 1;
        }
    }

    let mut unreceived = total;
    let global_deadline = Instant::now() + Duration::from_secs_f64(config.timeout);
    while unreceived > 0 && Instant::now() < global_deadline {
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        match recv_sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let data: &[u8] =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                let ip_hdr_len = ((data[0] & 0x0F) as usize) * 4;
                let icmp_body = &data[ip_hdr_len..];

                if let Some((icmp_type, icmp_code, 17, transport)) = parse_icmp_error(icmp_body) {
                    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                    for probe in &mut probes {
                        if probe.marker == dst_port && !probe.received {
                            probe.rtt_ms = probe.sent_at.elapsed().as_secs_f64() * 1000.0;
                            probe.received = true;
                            unreceived -= 1;
                            let ip = from.as_socket().unwrap().ip();
                            if hop_addrs[probe.ttl as usize].is_none() {
                                hop_addrs[probe.ttl as usize] = Some(ip);
                            }
                            if icmp_type == ICMP_DEST_UNREACH && icmp_code == 3 {
                                if target_reached_at.is_none() || probe.ttl < target_reached_at.unwrap() {
                                    target_reached_at = Some(probe.ttl);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                eprintln!("traceroute: recv error: {e}");
                break;
            }
        }
    }

    for ttl in config.first_ttl..=config.max_hops {
        let hop_probes: Vec<&Probe> = probes.iter().filter(|p| p.ttl == ttl).collect();
        let addr = hop_addrs[ttl as usize].map(|ip| SocketAddr::new(ip, 0));
        print_hop(ttl, addr, &hop_probes);
        if target_reached_at == Some(ttl) {
            break;
        }
    }

    Ok(())
}

fn run_icmp(config: &Config, target: SocketAddr) -> io::Result<()> {
    let sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::ICMPV4),
    )
    .map_err(|e| {
        eprintln!("traceroute: failed to create raw ICMP socket: {e}");
        eprintln!("(try running with sudo)");
        io::Error::new(io::ErrorKind::PermissionDenied, "raw socket failed")
    })?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;

    let id = (process::id() & 0xFFFF) as u16;
    let target_addr = SockAddr::from(target);

    let num_hops = (config.max_hops - config.first_ttl + 1) as usize;
    let total = num_hops * config.nqueries as usize;
    let mut probes: Vec<Probe> = Vec::with_capacity(total);
    let mut hop_addrs: Vec<Option<IpAddr>> = vec![None; (config.max_hops + 1) as usize];
    let mut target_reached_at: Option<u8> = None;

    let mut global_seq: u16 = 0;
    for ttl in config.first_ttl..=config.max_hops {
        sock.set_ttl_v4(ttl as u32)?;
        for _ in 0..config.nqueries {
            let packet = build_echo_request(id, global_seq, &[0u8; PROBE_PAYLOAD_SIZE]);
            let sent_at = Instant::now();
            sock.send_to(&packet, &target_addr).ok();
            probes.push(Probe { ttl, marker: global_seq, sent_at, received: false, rtt_ms: 0.0 });
            global_seq = global_seq.wrapping_add(1);
        }
    }

    let mut unreceived = total;
    let global_deadline = Instant::now() + Duration::from_secs_f64(config.timeout);
    while unreceived > 0 && Instant::now() < global_deadline {
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let data: &[u8] =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                let ip_hdr_len = ((data[0] & 0x0F) as usize) * 4;
                let icmp_body = &data[ip_hdr_len..];

                // Case 1: Echo Reply → we reached the destination.
                if let Some((rid, rseq, _)) = parse_echo_reply(icmp_body) {
                    if rid == id {
                        for probe in &mut probes {
                            if probe.marker == rseq && !probe.received {
                                probe.rtt_ms =
                                    probe.sent_at.elapsed().as_secs_f64() * 1000.0;
                                probe.received = true;
                                unreceived -= 1;
                                let ip = from.as_socket().unwrap().ip();
                                if hop_addrs[probe.ttl as usize].is_none() {
                                    hop_addrs[probe.ttl as usize] = Some(ip);
                                }
                                if target_reached_at.is_none() || probe.ttl < target_reached_at.unwrap() {
                                    target_reached_at = Some(probe.ttl);
                                }
                                break;
                            }
                        }
                    }
                } else if let Some((ICMP_TIME_EXCEEDED, 0, 1, transport)) =
                    parse_icmp_error(icmp_body)
                { // Case 2: Time Exceeded (Type 11, Code 0) from an intermediate router.
                    let inner_id = u16::from_be_bytes([transport[4], transport[5]]);
                    let inner_seq = u16::from_be_bytes([transport[6], transport[7]]);
                    if inner_id == id {
                        for probe in &mut probes {
                            if probe.marker == inner_seq && !probe.received {
                                probe.rtt_ms =
                                    probe.sent_at.elapsed().as_secs_f64() * 1000.0;
                                probe.received = true;
                                unreceived -= 1;
                                let ip = from.as_socket().unwrap().ip();
                                if hop_addrs[probe.ttl as usize].is_none() {
                                    hop_addrs[probe.ttl as usize] = Some(ip);
                                }
                                break;
                            }
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                eprintln!("traceroute: recv error: {e}");
                break;
            }
        }
    }

    // ── Phase 3: PRINT in TTL order, stop at target ──
    for ttl in config.first_ttl..=config.max_hops {
        let hop_probes: Vec<&Probe> = probes.iter().filter(|p| p.ttl == ttl).collect();
        let addr = hop_addrs[ttl as usize].map(|ip| SocketAddr::new(ip, 0));
        print_hop(ttl, addr, &hop_probes);
        if target_reached_at == Some(ttl) {
            break;
        }
    }

    Ok(())
}

fn print_hop(ttl: u8, hop_addr: Option<SocketAddr>, probes: &[&Probe]) {
    print!(" {:2}  ", ttl);

    if hop_addr.is_none() {
        for _ in probes {
            print!("* ");
        }
        println!();
        return;
    }

    let ip = hop_addr.unwrap().ip();
    print!("{} ({})  ", ip, ip);

    for p in probes {
        if p.received {
            print!("{:.3} ms  ", p.rtt_ms);
        } else {
            print!("*  ");
        }
    }
    println!();
}

fn resolve_host(host: &str) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(SocketAddr::new(ip.into(), 0));
    }
    let addr_str = format!("{host}:0");
    let mut addrs = addr_str.to_socket_addrs()?;
    addrs
        .find(|a| a.is_ipv4())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no IPv4 address found"))
}
