mod arp;
mod config;
mod ethernet;
mod ip;
mod socket;
mod stack;
mod tap;
mod tcp;
mod util;

use std::io::Write;
use std::process;
use std::time::Duration;

use clap::Parser;
use config::{parse_addr, Config};
use stack::TcpStack;

fn main() {
    let config = Config::parse();
    let our_ip = config.our_ip();

    let mut stack = TcpStack::new(&config.tap_name, our_ip).unwrap_or_else(|e| {
        eprintln!("failed to open tap device '{}': {e}", config.tap_name);
        process::exit(1);
    });

    println!(
        "TCP-stack: tap='{}' mac={} ip={}",
        config.tap_name,
        mac_str(stack.our_mac),
        ip_str(stack.our_ip),
    );

    let (remote_ip, remote_port) = match config.connect.as_ref().and_then(|s| parse_addr(s)) {
        Some(addr) => addr,
        None => {
            eprintln!("usage: --connect IP:PORT");
            process::exit(1);
        }
    };

    run_client(&mut stack, remote_ip, remote_port, &config.data);
}

fn run_client(stack: &mut TcpStack, remote_ip: [u8; 4], remote_port: u16, extra_data: &Option<String>) {
    let sock = stack.connect(remote_ip, remote_port).unwrap();

    // Wait for connection to establish
    println!("connecting to {}:{}...", ip_str(remote_ip), remote_port);
    while !stack.is_established(&sock) {
        stack.poll().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    println!("connected");

    // Send request
    let request = extra_data.clone().unwrap_or_else(|| {
        format!(
            "GET / HTTP/1.0\r\nHost: {}.{}.{}.{}\r\nConnection: close\r\n\r\n",
            remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3],
        )
    });
    stack.send(&sock, request.as_bytes());
    println!("request sent ({} bytes)", request.len());

    // Read response
    while !stack.is_closed(&sock) {
        stack.poll().unwrap();
        std::thread::sleep(Duration::from_millis(1));

        let data = stack.recv(&sock);
        if !data.is_empty() {
            if let Ok(text) = std::str::from_utf8(&data) {
                print!("{text}");
                let _ = std::io::stdout().flush();
            }
        }

        // Server closed (CloseWait) — send our FIN
        if matches!(stack.state(&sock), Some(tcp::TcpState::CloseWait)) {
            stack.close(&sock);
        }
    }
    println!("\nconnection closed.");
}

fn ip_str(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn mac_str(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
