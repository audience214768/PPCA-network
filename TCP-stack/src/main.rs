mod arp;
mod config;
mod ethernet;
mod ip;
mod tap;
mod tcp;
mod util;

use std::process;
use std::time::Instant;

use clap::Parser;
use ethernet::{ETH_TYPE_ARP, ETH_TYPE_IPV4};

use config::Config;
use tap::TapDevice;

fn mac_to_string(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn ip_to_string(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn main() {
    let config = Config::parse();
    let our_ip = config.our_ip();

    let tap = TapDevice::open(&config.tap_name).unwrap_or_else(|e| {
        eprintln!("failed to open tap device '{}': {e}", config.tap_name);
        eprintln!("(try running with sudo, and ensure the device exists)");
        process::exit(1);
    });

    let our_mac = tap.mac;
    let mut arp_cache = arp::ArpCache::new();
    let mut tcp_manager = tcp::TcpManager::new();

    if let Some(port) = config.listen {
        tcp_manager.listen(port);
        println!("TCP: listening on port {}", port);
    }

    println!(
        "TCP-stack: tap='{}' mac={} ip={}",
        tap.name,
        mac_to_string(our_mac),
        ip_to_string(our_ip),
    );
    println!("listening for frames...");

    let mut buf = vec![0u8; 65536];
    loop {
        let now = Instant::now();

        // 1. ARP tick: retry pending requests, drop timed-out entries
        let tick = arp_cache.tick(now);
        for ip_addr in &tick.retry_ips {
            println!(
                "> ARP: retry request for {} (who-has?)",
                ip_to_string(*ip_addr),
            );
            let request = arp::build_arp_request(our_mac, our_ip, *ip_addr);
            let frame = ethernet::build_frame(
                ethernet::BROADCAST_MAC,
                our_mac,
                ETH_TYPE_ARP,
                &request,
            );
            let _ = tap.write_frame(&frame);
            arp_cache.record_request(*ip_addr, now);
        }
        for ip_addr in &tick.timed_out_ips {
            println!("> ARP: resolution timed out for {}", ip_to_string(*ip_addr));
        }

        let retransmits = tcp_manager.poll_retransmit(now);
        for (key, seg) in &retransmits {
            let tcp_seg = tcp::build_tcp_segment(
                our_ip,
                key.2,
                key.1,
                seg.dst_port,
                seg.seq,
                seg.ack,
                seg.flags,
                tcp::DEFAULT_WINDOW,
                &seg.payload,
            );
            let ip_pkt = ip::build_ipv4(our_ip, key.2, ip::IP_PROTO_TCP, 64, &tcp_seg);
            if let Some(dst_mac) = arp_cache.lookup(key.2) {
                let eth_frame = ethernet::build_frame(dst_mac, our_mac, ETH_TYPE_IPV4, &ip_pkt);
                let _ = tap.write_frame(&eth_frame);
                tcp_manager.record_sent(key, &tcp_seg, now);
            }
        }

        // 3. Read incoming frames
        match tap.read_frame(&mut buf) {
            Ok(n) => {
                let data = &buf[..n];
                let (hdr, payload) = match ethernet::parse_frame(data) {
                    Some(v) => v,
                    None => continue,
                };

                match hdr.ethertype {
                    ETH_TYPE_ARP => {
                        let arp_pkt = match arp::parse_arp(payload) {
                            Some(p) => p,
                            None => continue,
                        };

                        arp_cache.learn(arp_pkt.spa, arp_pkt.sha);

                        if arp_pkt.oper == arp::ARP_OP_REQUEST && arp_pkt.tpa == our_ip {
                            println!(
                                "> ARP: who-has {}? tell {}",
                                ip_to_string(arp_pkt.tpa),
                                ip_to_string(arp_pkt.spa),
                            );
                            let reply = arp::build_arp_reply(
                                our_mac, our_ip, arp_pkt.sha, arp_pkt.spa,
                            );
                            let frame = ethernet::build_frame(
                                arp_pkt.sha, our_mac, ETH_TYPE_ARP, &reply,
                            );
                            if let Err(e) = tap.write_frame(&frame) {
                                eprintln!("write error: {e}");
                            } else {
                                println!(
                                    "  <- ARP reply: {} is-at {}",
                                    ip_to_string(our_ip),
                                    mac_to_string(our_mac),
                                );
                            }
                        } else if arp_pkt.oper == arp::ARP_OP_REPLY {
                            println!(
                                "> ARP: reply {} is-at {}",
                                ip_to_string(arp_pkt.spa),
                                mac_to_string(arp_pkt.sha),
                            );
                            let queued = arp_cache.insert(arp_pkt.spa, arp_pkt.sha);
                            if !queued.is_empty() {
                                println!(
                                    "  -> drained {} queued packet(s) for {}",
                                    queued.len(),
                                    ip_to_string(arp_pkt.spa),
                                );
                                for qpkt in queued {
                                    let frame = ethernet::build_frame(
                                        arp_pkt.sha, our_mac,
                                        ETH_TYPE_IPV4, &qpkt,
                                    );
                                    let _ = tap.write_frame(&frame);
                                }
                            }
                        }
                    }
                    ETH_TYPE_IPV4 => {
                        let (ip_hdr, ip_payload) = match ip::parse_ipv4(payload) {
                            Some(v) => v,
                            None => continue,
                        };

                        arp_cache.learn(ip_hdr.src, hdr.src);

                        match ip_hdr.protocol {
                            ip::IP_PROTO_ICMP => {
                                if let Some(reply) = ip::build_icmp_echo_reply(ip_payload) {
                                    let ip_pkt = ip::build_ipv4(
                                        our_ip, ip_hdr.src,
                                        ip::IP_PROTO_ICMP, 64, &reply,
                                    );
                                    let eth_frame = ethernet::build_frame(
                                        hdr.src, our_mac, ETH_TYPE_IPV4, &ip_pkt,
                                    );
                                    let _ = tap.write_frame(&eth_frame);
                                    println!(
                                        "> ICMP: echo reply {} -> {} ({} bytes)",
                                        ip_to_string(ip_hdr.dst),
                                        ip_to_string(ip_hdr.src),
                                        ip_payload.len(),
                                    );
                                }
                            }
                            ip::IP_PROTO_TCP => {
                                if !tcp::verify_tcp_checksum(ip_hdr.src, ip_hdr.dst, ip_payload) {
                                    continue;
                                }

                                let (tcp_hdr, tcp_data) =
                                    match tcp::parse_tcp(ip_payload) {
                                        Some(v) => v,
                                        None => continue,
                                    };

                                let (key, outgoing) = tcp_manager.process(
                                    our_ip, ip_hdr.src,
                                    &tcp_hdr, tcp_data, now,
                                );

                                for seg in &outgoing {
                                    let dst_mac = arp_cache.lookup(ip_hdr.src);
                                    if let Some(mac) = dst_mac {
                                        let seg_bytes = tcp::build_tcp_segment(
                                            our_ip, ip_hdr.src,
                                            tcp_hdr.dst_port, seg.dst_port,
                                            seg.seq, seg.ack, seg.flags,
                                            tcp::DEFAULT_WINDOW, &seg.payload,
                                        );
                                        let ip_pkt = ip::build_ipv4(
                                            our_ip, ip_hdr.src,
                                            ip::IP_PROTO_TCP, 64, &seg_bytes,
                                        );
                                        let eth_frame = ethernet::build_frame(
                                            mac, our_mac, ETH_TYPE_IPV4, &ip_pkt,
                                        );
                                        let _ = tap.write_frame(&eth_frame);
                                        if let Some(ref k) = key {
                                            tcp_manager.record_sent(k, &seg_bytes, now);
                                        }
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }
                    _ => continue,
                }
            }
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }
}
