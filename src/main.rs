use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};

fn main() -> anyhow::Result<()> {
    // 1. Discover available network devices
    let devices = Device::list()?;
    if devices.is_empty() {
        eprintln!("No network interfaces found. Ensure sufficient privileges (e.g. sudo or CAP_NET_RAW).");
        return Ok(());
    }

    println!("Available network devices:");
    for (i, dev) in devices.iter().enumerate() {
        let desc = dev.desc.as_deref().unwrap_or("no description");
        println!("  [{}] {} ({})", i, dev.name, desc);
    }

    // 2. Select default capture device
    let default_device = match Device::lookup()? {
        Some(dev) => dev,
        None => devices[0].clone(),
    };

    println!("\nCapturing on device: '{}'...", default_device.name);

    // 3. Configure the handle for capturing packets
    let mut cap = Capture::from_device(default_device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .immediate_mode(true)
        .open()?;

    // 4. (Optional) Filter packets using BPF syntax
    // Example: cap.filter("tcp or udp", true)?;

    println!("Listening for packets (press Ctrl+C to stop)...\n");

    let mut packet_count = 0;

    // 5. Packet capture loop
    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        let ts = packet.header.ts;
        let len = packet.header.len;

        print!(
            "[{:>5}] {}.{:06} | Length: {:>5} bytes | ",
            packet_count, ts.tv_sec, ts.tv_usec, len
        );

        match SlicedPacket::from_ethernet(packet.data) {
            Ok(sliced) => {
                let transport_info = match sliced.transport {
                    Some(TransportSlice::Tcp(tcp)) => {
                        format!(
                            "TCP {}:{} -> {}:{}",
                            format_ip_src(&sliced.net),
                            tcp.source_port(),
                            format_ip_dst(&sliced.net),
                            tcp.destination_port()
                        )
                    }
                    Some(TransportSlice::Udp(udp)) => {
                        format!(
                            "UDP {}:{} -> {}:{}",
                            format_ip_src(&sliced.net),
                            udp.source_port(),
                            format_ip_dst(&sliced.net),
                            udp.destination_port()
                        )
                    }
                    Some(TransportSlice::Icmpv4(_)) => {
                        format!(
                            "ICMPv4 {} -> {}",
                            format_ip_src(&sliced.net),
                            format_ip_dst(&sliced.net)
                        )
                    }
                    Some(TransportSlice::Icmpv6(_)) => {
                        format!(
                            "ICMPv6 {} -> {}",
                            format_ip_src(&sliced.net),
                            format_ip_dst(&sliced.net)
                        )
                    }
                    Some(TransportSlice::Igmp(_)) => {
                        format!(
                            "IGMP {} -> {}",
                            format_ip_src(&sliced.net),
                            format_ip_dst(&sliced.net)
                        )
                    }
                    None => {
                        if let Some(net) = &sliced.net {
                            match net {
                                NetSlice::Ipv4(ipv4) => format!(
                                    "IPv4 {} -> {}",
                                    ipv4.header().source_addr(),
                                    ipv4.header().destination_addr()
                                ),
                                NetSlice::Ipv6(ipv6) => format!(
                                    "IPv6 {} -> {}",
                                    ipv6.header().source_addr(),
                                    ipv6.header().destination_addr()
                                ),
                                NetSlice::Arp(_) => "ARP packet".to_string(),
                            }
                        } else if let Some(link) = &sliced.link {
                            format!("Link Layer: {:?}", link)
                        } else {
                            "Non-IP packet".to_string()
                        }
                    }
                };
                println!("{}", transport_info);
            }
            Err(_) => {
                println!("Raw frame (could not dissect Ethernet header)");
            }
        }
    }

    Ok(())
}

fn format_ip_src(net: &Option<NetSlice>) -> String {
    match net {
        Some(NetSlice::Ipv4(ipv4)) => ipv4.header().source_addr().to_string(),
        Some(NetSlice::Ipv6(ipv6)) => ipv6.header().source_addr().to_string(),
        _ => "unknown".to_string(),
    }
}

fn format_ip_dst(net: &Option<NetSlice>) -> String {
    match net {
        Some(NetSlice::Ipv4(ipv4)) => ipv4.header().destination_addr().to_string(),
        Some(NetSlice::Ipv6(ipv6)) => ipv6.header().destination_addr().to_string(),
        _ => "unknown".to_string(),
    }
}
