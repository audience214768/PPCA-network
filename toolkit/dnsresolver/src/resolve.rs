use crate::cache::DnsCache;
use crate::message::{
    decode_message, encode_message, DnsHeader, DnsMessage, DnsQuestion, DnsRR, RData,
    CLASS_IN, RCODE_NXDOMAIN, TYPE_A, TYPE_CNAME,
};

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CNAME_DEPTH: usize = 16;
const MAX_ITERATIONS: usize = 30;
const MAX_GLUE_DEPTH: usize = 3;

pub fn resolve(
    name: &str,
    qtype: u16,
    cache: &DnsCache,
    verbose: bool,
) -> Vec<DnsRR> {
    let name = name.to_ascii_lowercase();

    if let Some(rrs) = cache.get(&name, qtype, CLASS_IN) {
        if verbose {
            eprintln!("[cache hit] {name} TYPE{qtype}");
        }
        return rrs;
    }
    if cache.is_nxdomain(&name, qtype, CLASS_IN) {
        if verbose {
            eprintln!("[negative cache] {name} TYPE{qtype}");
        }
        return vec![];
    }

    match resolve_iterative(&name, qtype, cache, verbose, 0) {
        Ok(rrs) => rrs,
        Err(e) => {
            if verbose {
                eprintln!("[resolve error] {name}: {e}");
            }
            vec![]
        }
    }
}

fn resolve_iterative(
    name: &str,
    qtype: u16,
    cache: &DnsCache,
    verbose: bool,
    glue_depth: usize,
) -> Result<Vec<DnsRR>, String> {
    let mut servers: Vec<(String, Ipv4Addr)> = get_nameservers(".", cache)?;
    let mut visited_ns = HashSet::new();
    let mut current_name = name.to_string();
    let mut cname_depth = 0;
    let mut cname_chain: Vec<DnsRR> = Vec::new();

    for _iteration in 0..MAX_ITERATIONS {
        if let Some(rrs) = cache.get(&current_name, qtype, CLASS_IN) {
            cname_chain.extend(rrs);
            return Ok(cname_chain);
        }

        if verbose {
            eprintln!(
                "[query] {current_name} TYPE{qtype} \u{2192} {} servers",
                servers.len()
            );
        }

        let (answers, authorities, additionals) = query_best_server(
            &current_name,
            qtype,
            &servers,
            cache,
            verbose,
        )?;

        if !answers.is_empty() {
            let matching = extract_matching(&answers, qtype);
            if !matching.is_empty() {
                cname_chain.extend(matching);
                return Ok(cname_chain);
            }

            if qtype != TYPE_CNAME {
                if let Some(cname_rr) = find_cname(&answers) {
                    if cname_depth >= MAX_CNAME_DEPTH {
                        return Err("CNAME depth exceeded".into());
                    }
                    cname_depth += 1;
                    current_name = cname_target(&cname_rr).to_string();
                    cname_chain.push(cname_rr);
                    servers = get_nameservers(&current_name, cache)?;
                    continue;
                }
            }

            return Ok(cname_chain);
        }

        if let Some(new_servers) =
            extract_referral(&authorities, &additionals, cache, verbose, glue_depth)
        {
            if new_servers.is_empty() {
                return Err("empty referral".into());
            }
            let ns_key: Vec<String> = new_servers.iter().map(|(n, _)| n.clone()).collect();
            let ns_key_str = ns_key.join(",");
            if !visited_ns.insert(ns_key_str) {
                return Err("referral cycle detected".into());
            }
            servers = new_servers;
            continue;
        }

        if is_nxdomain(&authorities) {
            let soa_ttl = extract_soa_minimum(&authorities);
            cache.put_nxdomain(name, qtype, CLASS_IN, soa_ttl);
            if verbose {
                eprintln!("[nxdomain] {name}");
            }
            return Ok(vec![]);
        }

        return Err("no useful response from any server".into());
    }

    Err("too many iterations".into())
}

fn query_best_server(
    name: &str,
    qtype: u16,
    servers: &[(String, Ipv4Addr)],
    cache: &DnsCache,
    verbose: bool,
) -> Result<(Vec<DnsRR>, Vec<DnsRR>, Vec<DnsRR>), String> {
    let mut last_err = String::new();

    for (ns_name, ip) in servers {
        let addr = SocketAddr::V4(SocketAddrV4::new(*ip, 53));
        match send_query(addr, name, qtype) {
            Ok(msg) => {
                let answers = msg.answers;
                let authorities = msg.authorities;
                let additionals = msg.additionals;

                cache.put_all(&answers);
                cache.put_all(&authorities);
                cache.put_all(&additionals);

                if msg.header.rcode() == RCODE_NXDOMAIN {
                    return Ok((vec![], authorities, additionals));
                }

                return Ok((answers, authorities, additionals));
            }
            Err(e) => {
                if verbose {
                    eprintln!("[server {ns_name} ({ip})] {e}");
                }
                last_err = format!("{ns_name}: {e}");
            }
        }
    }
    Err(last_err)
}

fn send_query(server: SocketAddr, name: &str, qtype: u16) -> Result<DnsMessage, String> {
    let query = DnsMessage {
        header: DnsHeader {
            id: fastrand::u16(..),
            flags: 0x0100,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        },
        questions: vec![DnsQuestion {
            qname: name.to_string(),
            qtype,
            qclass: CLASS_IN,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    let wire = encode_message(&query);

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    socket
        .set_read_timeout(Some(QUERY_TIMEOUT))
        .map_err(|e| format!("set_timeout: {e}"))?;
    socket
        .send_to(&wire, server)
        .map_err(|e| format!("send: {e}"))?;

    let mut buf = [0u8; 4096];
    let (n, _from) = socket.recv_from(&mut buf).map_err(|e| format!("recv: {e}"))?;

    decode_message(&buf[..n]).ok_or_else(|| "invalid DNS response".into())
}

fn extract_referral(
    authorities: &[DnsRR],
    additionals: &[DnsRR],
    cache: &DnsCache,
    verbose: bool,
    glue_depth: usize,
) -> Option<Vec<(String, Ipv4Addr)>> {
    let ns_names: Vec<String> = authorities
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::NS(name) => Some(name.clone()),
            _ => None,
        })
        .collect();

    if ns_names.is_empty() {
        return None;
    }

    let glue: Vec<(String, Ipv4Addr)> = additionals
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::A(ip) => Some((rr.name.clone(), Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))),
            _ => None,
        })
        .collect();

    let mut result = Vec::new();
    for ns in &ns_names {
        if let Some((_, ip)) = glue.iter().find(|(n, _)| n == ns) {
            result.push((ns.clone(), *ip));
            continue;
        }
        if let Some(a_records) = cache.get(ns, TYPE_A, CLASS_IN) {
            for a in a_records {
                if let RData::A(ip) = a.rdata {
                    result.push((ns.clone(), Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])));
                }
            }
            continue;
        }
        if verbose {
            eprintln!("[no glue] resolving NS {ns}");
        }
        if glue_depth >= MAX_GLUE_DEPTH {
            continue;
        }
        match resolve_iterative(ns, TYPE_A, cache, verbose, glue_depth + 1) {
            Ok(rrs) => {
                for rr in rrs {
                    if let RData::A(ip) = rr.rdata {
                        result.push((ns.clone(), Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])));
                    }
                }
            }
            Err(_) => {}
        }
    }

    Some(result)
}

fn get_nameservers(name: &str, cache: &DnsCache) -> Result<Vec<(String, Ipv4Addr)>, String> {
    let mut labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    labels.push("");

    for i in 0..labels.len() {
        let zone = if i == labels.len() - 1 {
            ".".to_string()
        } else {
            labels[i..].join(".") + "."
        };

        let ns_ips = cache.get_ns_ips(&zone);
        if !ns_ips.is_empty() {
            return Ok(ns_ips);
        }
    }

    Err(format!("no NS records found for {name}"))
}

fn find_cname(rrs: &[DnsRR]) -> Option<DnsRR> {
    rrs.iter().find(|rr| matches!(rr.rdata, RData::CNAME(_))).cloned()
}

fn cname_target(rr: &DnsRR) -> &str {
    match &rr.rdata {
        RData::CNAME(name) => name,
        _ => unreachable!(),
    }
}

fn extract_matching(rrs: &[DnsRR], qtype: u16) -> Vec<DnsRR> {
    rrs.iter()
        .filter(|rr| rr.rtype == qtype)
        .cloned()
        .collect()
}

fn is_nxdomain(authorities: &[DnsRR]) -> bool {
    authorities.iter().any(|rr| rr.rtype == 6)
}

fn extract_soa_minimum(authorities: &[DnsRR]) -> u32 {
    for rr in authorities {
        if let RData::SOA { minimum, .. } = &rr.rdata {
            return *minimum;
        }
    }
    60
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::DnsCache;
    use crate::message::{CLASS_IN, TYPE_A, TYPE_NS};

    fn setup_cache_with_root() -> DnsCache {
        let cache = DnsCache::new();
        cache.put(&DnsRR {
            name: ".".to_string(),
            rtype: TYPE_NS,
            class: CLASS_IN,
            ttl: 3600000,
            rdata: RData::NS("a.root-servers.net.".to_string()),
        });
        cache.put(&DnsRR {
            name: "a.root-servers.net.".to_string(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl: 3600000,
            rdata: RData::A([198, 41, 0, 4]),
        });
        cache
    }

    #[test]
    fn test_cache_hit() {
        let cache = setup_cache_with_root();
        cache.put(&DnsRR {
            name: "example.com.".to_string(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl: 300,
            rdata: RData::A([93, 184, 216, 34]),
        });

        let results = resolve("example.com.", TYPE_A, &cache, false);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].rdata, RData::A([93, 184, 216, 34])));
    }

    #[test]
    fn test_negative_cache() {
        let cache = setup_cache_with_root();
        cache.put_nxdomain("noexist.com.", TYPE_A, CLASS_IN, 60);
        let results = resolve("noexist.com.", TYPE_A, &cache, false);
        assert!(results.is_empty());
    }
}
