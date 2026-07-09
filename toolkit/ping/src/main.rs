mod config;
mod icmp;
mod stats;

use std::io;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use clap::Parser;
use socket2::{Domain, Protocol, Socket, SockAddr, Type};

use config::Config;
use icmp::{build_echo_request, parse_echo_reply};
use stats::RttStats;

fn main() {
    let config = Config::parse();

    let target = match resolve_host(&config.host) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("ping: {}: {}", config.host, e);
            process::exit(2);
        }
    };
    let resolved_ip = target.ip().to_string();

    let sock_type: Type = (libc::SOCK_RAW as i32).into();
    let socket = match Socket::new(Domain::IPV4, sock_type, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ping: failed to create raw socket: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs_f64(config.timeout))) {
        eprintln!("ping: set_read_timeout failed: {e}");
        process::exit(1);
    }
    let id = (process::id() & 0xFFFF) as u16;

    let payload = vec![0u8; config.size];

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    println!(
        "PING {} ({}): {} data bytes",
        config.host,
        resolved_ip,
        config.size
    );

    let mut stats = RttStats::new();
    let mut seq: u16 = 0;
    let target_addr = SockAddr::from(target);

    while running.load(Ordering::Relaxed) {
        if let Some(c) = config.count {
            if stats.sent >= c {
                break;
            }
        }

        // Build and send.
        let packet = build_echo_request(id, seq, &payload);
        let sent_at = Instant::now();

        if let Err(e) = socket.send_to(&packet, &target_addr) {
            eprintln!("ping: sendto: {e}");
            break;
        }
        stats.sent += 1;

        // Receive. socket2 0.6 uses MaybeUninit<u8>.
        let mut buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let rtt = sent_at.elapsed().as_secs_f64() * 1000.0;

                // SAFETY: `n` bytes are initialized.
                let data: &[u8] = unsafe {
                    std::slice::from_raw_parts(buf.as_ptr() as *const u8, n)
                };

                // IP header length in 32-bit words (IHL = low nibble of byte 0).
                let ip_header_len = ((data[0] & 0x0F) as usize) * 4;
                if n >= ip_header_len + 8 {
                    if let Some((rid, rseq, _reply_payload)) =
                        parse_echo_reply(&data[ip_header_len..])
                    {
                        if rid == id {
                            let ttl = data[8];
                            let data_len = n - ip_header_len;
                            println!(
                                "{} bytes from {}: icmp_seq={} ttl={} time={:.2} ms",
                                data_len, from.as_socket_ipv4().unwrap(), rseq, ttl, rtt
                            );
                            stats.record(rtt);
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                println!("Request timeout for icmp_seq {seq}");
            }
            Err(e) => {
                eprintln!("ping: recvfrom: {e}");
                break;
            }
        }

        seq = seq.wrapping_add(1);

        if running.load(Ordering::Relaxed) {
            if let Some(c) = config.count {
                if stats.sent >= c {
                    break;
                }
            }
            sleep(Duration::from_secs_f64(config.interval));
        }
    }

    // ── Summary ─────────────────────────────────────────────────
    stats.print_summary(&config.host, &resolved_ip);
}

/// Resolve a hostname to a `SocketAddr`. Returns the first IPv4 result.
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

fn ctrlc_handler(running: Arc<AtomicBool>) -> Result<(), ()> {
    unsafe {
        let prev = libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
        if prev == libc::SIG_ERR {
            return Err(());
        }
    }
    let ptr = Arc::into_raw(running);
    unsafe {
        SIGINT_FLAG = ptr as *mut AtomicBool;
    }
    Ok(())
}

static mut SIGINT_FLAG: *mut AtomicBool = std::ptr::null_mut();

extern "C" fn sigint_handler(_sig: i32) {
    unsafe {
        if !SIGINT_FLAG.is_null() {
            (*SIGINT_FLAG).store(false, Ordering::SeqCst);
        }
    }
}
