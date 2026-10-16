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
