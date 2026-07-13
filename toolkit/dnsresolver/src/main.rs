mod cache;
mod message;
mod resolve;

use std::net::UdpSocket;
use std::process;
use std::sync::Arc;

use clap::Parser;

use cache::DnsCache;
use message::{
    decode_message, encode_message, DnsHeader, DnsMessage, DnsRR, CLASS_IN, RCODE_NOERROR,
    RCODE_NXDOMAIN,
};

#[derive(Parser, Debug)]
#[command(name = "dnsresolver", about = "Recursive DNS resolver from root")]
struct Config {
    #[arg(long = "port", default_value = "5353")]
    port: u16,

    #[arg(long = "root", default_value = "root.hints")]
    root: String,

    #[arg(long = "verbose")]
    verbose: bool,
}

fn main() {
    let config = Config::parse();

    let cache = Arc::new(DnsCache::new());
    let root_path = if config.root.starts_with('/') {
        config.root.clone()
    } else {
        format!(
            "{}/../{}",
            env!("CARGO_MANIFEST_DIR"),
            config.root
        )
    };
    if let Err(e) = cache.load_root_hints(&root_path) {
        eprintln!("Warning: could not load root hints from {root_path}: {e}");
        eprintln!("Hard-coding root server IPs as fallback.");
        process::exit(1);
    }

    let addr = format!("127.0.0.1:{}", config.port);
    let socket = UdpSocket::bind(&addr).unwrap_or_else(|e| {
        eprintln!("dnsresolver: bind {addr}: {e}");
        process::exit(1);
    });
    println!("DNS resolver listening on {addr}");

    let socket = Arc::new(socket);

    let mut buf = [0u8; 2048];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let cache = cache.clone();
                let sock = socket.clone();
                let verbose = config.verbose;
                std::thread::spawn(move || {
                    handle_query(&buf[..n], from, &cache, &sock, verbose);
                });
            }
            Err(e) => {
                eprintln!("recv error: {e}");
            }
        }
    }
}

fn handle_query(data: &[u8], client: std::net::SocketAddr, cache: &DnsCache, sock: &UdpSocket, verbose: bool) {
    let query = match decode_message(data) {
        Some(m) => m,
        None => {
            eprintln!("[{client}] invalid query");
            return;
        }
    };

    if verbose {
        let questions: Vec<String> = query
            .questions
            .iter()
            .map(|q| format!("{} TYPE{}", q.qname, q.qtype))
            .collect();
        eprintln!("[{client}] query: {}", questions.join(", "));
    }

    let mut answers = Vec::new();
    let mut rcode = RCODE_NOERROR;

    for q in &query.questions {
        let results = resolve::resolve(&q.qname, q.qtype, cache, verbose);
        if results.is_empty() && cache.is_nxdomain(&q.qname, q.qtype, CLASS_IN) {
            rcode = RCODE_NXDOMAIN;
        }
        answers.extend(results);
    }

    let response = build_response(&query, &answers, rcode);
    let wire = encode_message(&response);

    if let Err(e) = sock.send_to(&wire, client) {
        eprintln!("[{client}] send error: {e}");
    } else if verbose {
        eprintln!(
            "[{client}] sent {} answer bytes ({} RRs)",
            wire.len(),
            answers.len()
        );
    }
}

fn build_response(query: &DnsMessage, answers: &[DnsRR], rcode: u8) -> DnsMessage {
    DnsMessage {
        header: DnsHeader {
            id: query.header.id,
            flags: 0x8000 | 0x0080 | (rcode as u16),
            qdcount: query.header.qdcount,
            ancount: answers.len() as u16,
            nscount: 0,
            arcount: 0,
        },
        questions: query.questions.clone(),
        answers: answers.to_vec(),
        authorities: vec![],
        additionals: vec![],
    }
}