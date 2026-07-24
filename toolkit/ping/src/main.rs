mod config;
mod icmp;
mod stats;

use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use config::Config;
use icmp::{build_echo_request, parse_echo_reply};
use stats::RttStats;

fn main() {
    let config = Config::parse();

    let target = resolve_host(&config.host).unwrap_or_else(|e| {
        eprintln!("ping: {}: {}", config.host, e);
        process::exit(2);
    });
    let resolved_ip = target.ip().to_string();

    let sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::ICMPV4),
    )
    .unwrap_or_else(|e| {
        eprintln!("ping: failed to create raw socket: {e}");
        eprintln!("(try running with sudo)");
        process::exit(1);
    });
    let recv_sock = sock.try_clone().unwrap_or_else(|e| {
        eprintln!("ping: failed to clone socket: {e}");
        process::exit(1);
    });

    let id = (process::id() & 0xFFFF) as u16;
    let payload = vec![0u8; config.size];
    let running = Arc::new(AtomicBool::new(true));
    let _ = ctrlc_handler(running.clone());

    println!(
        "PING {} ({}): {} data bytes",
        config.host, resolved_ip, config.size
    );

    let target_addr = SockAddr::from(target);
    let interval = Duration::from_secs_f64(config.interval);
    let timeout = Duration::from_secs_f64(config.timeout);

    let sent_times: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let stats = Arc::new(Mutex::new(RttStats::new()));

    let recv_running = running.clone();
    let recv_times = sent_times.clone();
    let recv_stats = stats.clone();
    let recv_handle = thread::spawn(move || {
        recv_sock
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();

        while recv_running.load(Ordering::Relaxed) {
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            match recv_sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let data: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    let ip_hdr_len = ((data[0] & 0x0F) as usize) * 4;

                    if let Some((rid, rseq, _)) = parse_echo_reply(&data[ip_hdr_len..]) {
                        if rid == id {
                            let mut times = recv_times.lock().unwrap();
                            if let Some(sent_at) = times.remove(&rseq) {
                                let rtt = sent_at.elapsed().as_secs_f64() * 1000.0;
                                println!(
                                    "{} bytes from {}: icmp_seq={} ttl={} time={:.2} ms",
                                    n - ip_hdr_len,
                                    from.as_socket().unwrap(),
                                    rseq,
                                    data[8],
                                    rtt,
                                );
                                recv_stats.lock().unwrap().record(rtt);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("ping: recvfrom: {e}");
                    break;
                }
            }

            // Report probes that have timed out.
            let now = Instant::now();
            let mut times = recv_times.lock().unwrap();
            let timed_out: Vec<u16> = times
                .iter()
                .filter(|(_, sent_at)| now - **sent_at > timeout)
                .map(|(seq, _)| *seq)
                .collect();
            for seq in timed_out {
                times.remove(&seq);
                println!("Request timeout for icmp_seq {}", seq);
            }
        }
    });

    // ── Sender (main thread) ──
    let mut seq: u16 = 0;
    let mut next_send = Instant::now();

    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        if let Some(c) = config.count {
            if stats.lock().unwrap().sent >= c {
                break;
            }
        }

        let packet = build_echo_request(id, seq, &payload);
        if sock.send_to(&packet, &target_addr).is_err() {
            break;
        }

        sent_times.lock().unwrap().insert(seq, Instant::now());
        stats.lock().unwrap().sent += 1;
        seq = seq.wrapping_add(1);

        next_send += interval;
        let now = Instant::now();
        if next_send > now {
            thread::sleep(next_send - now);
        } else {
            next_send = now;
        }
    }

    thread::sleep(timeout);
    running.store(false, Ordering::SeqCst);
    recv_handle.join().unwrap();

    {
        let times = sent_times.lock().unwrap();
        let mut seqs: Vec<u16> = times.keys().copied().collect();
        seqs.sort();
        for rseq in seqs {
            println!("Request timeout for icmp_seq {}", rseq);
        }
    }

    stats.lock().unwrap().print_summary(&config.host, &resolved_ip);
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

fn ctrlc_handler(running: Arc<AtomicBool>) -> Result<(), ()> {
    unsafe {
        let prev =
            libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
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
