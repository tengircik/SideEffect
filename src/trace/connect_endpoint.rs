use super::path_hint::split_top_level_arguments;
use crate::limits::MAX_RECORD_BYTES;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Read the requested destination from a supported literal strace `connect` sockaddr.
/// The destination describes the attempt regardless of the syscall result.
pub fn derive_connect_endpoint(syscall: &str, raw_arguments: &str) -> Option<SocketAddr> {
    if syscall != "connect" || raw_arguments.len() > MAX_RECORD_BYTES {
        return None;
    }
    let arguments = split_top_level_arguments(raw_arguments, 3)?;
    let [descriptor, sockaddr, length] = arguments.as_slice() else {
        return None;
    };
    let descriptor = descriptor.trim();
    let number = match descriptor.split_once('<') {
        Some((number, annotation)) if annotation.ends_with('>') => number,
        Some(_) => return None,
        None => descriptor,
    };
    number.parse::<i32>().ok()?;
    let sockaddr = sockaddr.trim().strip_prefix('{')?.strip_suffix('}')?;
    let fields = split_top_level_arguments(sockaddr, 5)?;
    match (fields.as_slice(), length.trim()) {
        (["sa_family=AF_INET", port, address], "16") => {
            let port = parse_port(port.trim().strip_prefix("sin_port=")?)?;
            let address: Ipv4Addr = address
                .trim()
                .strip_prefix("sin_addr=inet_addr(\"")?
                .strip_suffix("\")")?
                .parse()
                .ok()?;
            Some(SocketAddr::from((address, port)))
        }
        (["sa_family=AF_INET6", port, flow, address, scope], "28")
            if flow.trim() == "sin6_flowinfo=htonl(0)" && scope.trim() == "sin6_scope_id=0" =>
        {
            let port = parse_port(port.trim().strip_prefix("sin6_port=")?)?;
            let address: Ipv6Addr = address
                .trim()
                .strip_prefix("inet_pton(AF_INET6, \"")?
                .strip_suffix("\", &sin6_addr)")?
                .parse()
                .ok()?;
            Some(SocketAddr::from((address, port)))
        }
        _ => None,
    }
}

fn parse_port(value: &str) -> Option<u16> {
    let digits = value.strip_prefix("htons(")?.strip_suffix(')')?;
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4: &str = r#"3<TCP:[123]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16"#;
    const IPV6: &str = r#"3, {sa_family=AF_INET6, sin6_port=htons(1), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28"#;

    #[test]
    fn reads_literal_connect_destinations() {
        assert_eq!(
            derive_connect_endpoint("connect", IPV4),
            "127.0.0.1:80".parse().ok()
        );
        assert_eq!(
            derive_connect_endpoint("connect", IPV6),
            "[::1]:1".parse().ok()
        );
    }

    #[test]
    fn rejects_unsupported_or_malformed_destinations() {
        assert_eq!(derive_connect_endpoint("bind", IPV4), None);
        for arguments in [
            IPV4.replace("127.0.0.1", "localhost"),
            IPV4.replace("3<TCP:[123]>", "invalid"),
            IPV4.replace("htons(80)", "htons(65536)"),
            IPV4.replace("}, 16", "}, 12"),
            IPV4.replace("}, 16", ", sin_port=htons(99)}, 16"),
            IPV6.replace("sin6_scope_id=0", "sin6_scope_id=2"),
            "3, {sa_family=AF_UNIX, sun_path=\"/tmp/socket\"}, 16".to_owned(),
            "3, ...".to_owned(),
            "a".repeat(MAX_RECORD_BYTES + 1),
        ] {
            assert_eq!(derive_connect_endpoint("connect", &arguments), None);
        }
    }
}
