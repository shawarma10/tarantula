use std::time::{SystemTime, UNIX_EPOCH};
use etherparse::NetSlice;

pub fn format_ip_src(net: &Option<NetSlice>) -> String {
    match net {
        Some(NetSlice::Ipv4(ipv4)) => ipv4.header().source_addr().to_string(),
        Some(NetSlice::Ipv6(ipv6)) => ipv6.header().source_addr().to_string(),
        _ => "unknown".to_string(),
    }
}

pub fn format_ip_dst(net: &Option<NetSlice>) -> String {
    match net {
        Some(NetSlice::Ipv4(ipv4)) => ipv4.header().destination_addr().to_string(),
        Some(NetSlice::Ipv6(ipv6)) => ipv6.header().destination_addr().to_string(),
        _ => "unknown".to_string(),
    }
}

pub fn format_mac_address(address: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        address[0], address[1], address[2], address[3], address[4], address[5]
    )
}

fn format_chars(data: &[u8]) -> String {
    let mut buf = String::from('|');
    for byte in data {
        if byte.is_ascii_alphanumeric() {
            buf.push_str(&format!("{}", *byte as char));
        } else {
            buf.push('.');
        }
    }

    buf.push('|');
    buf
}

pub fn format_data(data: &[u8], bytes_per_line: usize) -> String {
    let mut current_line = 0;
    let mut line_bytes: Vec<u8> = Vec::new();
    let mut result = format!("\t{:08x}: ", current_line);

    for byte in data {
        line_bytes.push(*byte);
        result.push_str(&format!("{:02x} ", byte));
        if line_bytes.len() == bytes_per_line {
            current_line += bytes_per_line;
            result.push_str(&format_chars(&line_bytes));
            result.push_str(&format!("\n\t{:08x}: ", current_line));
            line_bytes.clear();
        }
    }

    if line_bytes.len() != 0 {
        result.push_str(&format_chars(&line_bytes));
    }

    result.push('\n');
    result
}

pub fn current_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
