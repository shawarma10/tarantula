use crate::{flags, helpers, json};
use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};
use pcap::{Active, Capture};

pub fn capture_loop(mut cap: Capture<Active>, flags: &flags::Flags) -> anyhow::Result<()> {
    let mut packet_count = 0;

    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        let ts = packet.header.ts;
        let len = packet.header.len;

        if flags.json {
            let json_packet = match SlicedPacket::from_ethernet(packet.data) {
                Ok(sliced) => match sliced.transport {
                    Some(TransportSlice::Tcp(tcp)) => json::JsonPacket {
                        protocol: "TCP".to_string(),
                        length: len,
                        time: helpers::current_unix_secs()?,
                        src_ip: Some(helpers::format_ip_src(&sliced.net)),
                        dst_ip: Some(helpers::format_ip_dst(&sliced.net)),
                        src_port: Some(tcp.source_port()),
                        dst_port: Some(tcp.destination_port()),
                    },

                    Some(TransportSlice::Udp(udp)) => json::JsonPacket {
                        protocol: "UDP".to_string(),
                        length: len,
                        time: helpers::current_unix_secs()?,
                        src_ip: Some(helpers::format_ip_src(&sliced.net)),
                        dst_ip: Some(helpers::format_ip_dst(&sliced.net)),
                        src_port: Some(udp.source_port()),
                        dst_port: Some(udp.destination_port()),
                    },

                    Some(TransportSlice::Icmpv4(_)) => json::JsonPacket {
                        protocol: "ICMPv4".to_string(),
                        length: len,
                        time: helpers::current_unix_secs()?,
                        src_ip: Some(helpers::format_ip_src(&sliced.net)),
                        dst_ip: Some(helpers::format_ip_dst(&sliced.net)),
                        src_port: None,
                        dst_port: None,
                    },

                    Some(TransportSlice::Icmpv6(_)) => json::JsonPacket {
                        protocol: "ICMPv6".to_string(),
                        length: len,
                        time: helpers::current_unix_secs()?,
                        src_ip: Some(helpers::format_ip_src(&sliced.net)),
                        dst_ip: Some(helpers::format_ip_dst(&sliced.net)),
                        src_port: None,
                        dst_port: None,
                    },

                    Some(TransportSlice::Igmp(_)) => json::JsonPacket {
                        protocol: "IGMP".to_string(),
                        length: len,
                        time: helpers::current_unix_secs()?,
                        src_ip: Some(helpers::format_ip_src(&sliced.net)),
                        dst_ip: Some(helpers::format_ip_dst(&sliced.net)),
                        src_port: None,
                        dst_port: None,
                    },

                    None => match &sliced.net {
                        Some(NetSlice::Ipv4(ipv4)) => json::JsonPacket {
                            protocol: "IPv4".to_string(),
                            length: len,
                            time: helpers::current_unix_secs()?,
                            src_ip: Some(ipv4.header().source_addr().to_string()),
                            dst_ip: Some(ipv4.header().destination_addr().to_string()),
                            src_port: None,
                            dst_port: None,
                        },

                        Some(NetSlice::Ipv6(ipv6)) => json::JsonPacket {
                            protocol: "IPv6".to_string(),
                            length: len,
                            time: helpers::current_unix_secs()?,
                            src_ip: Some(ipv6.header().source_addr().to_string()),
                            dst_ip: Some(ipv6.header().destination_addr().to_string()),
                            src_port: None,
                            dst_port: None,
                        },

                        Some(NetSlice::Arp(_)) => json::JsonPacket {
                            protocol: "ARP".to_string(),
                            length: len,
                            time: helpers::current_unix_secs()?,
                            src_ip: None,
                            dst_ip: None,
                            src_port: None,
                            dst_port: None,
                        },

                        None => {
                            if let Some(LinkSlice::Ethernet2(_)) = &sliced.link {
                                json::JsonPacket {
                                    protocol: "Ethernet".to_string(),
                                    length: len,
                                    time: helpers::current_unix_secs()?,
                                    src_ip: None,
                                    dst_ip: None,
                                    src_port: None,
                                    dst_port: None,
                                }
                            } else {
                                json::JsonPacket {
                                    protocol: "Unknown".to_string(),
                                    length: len,
                                    time: helpers::current_unix_secs()?,
                                    src_ip: None,
                                    dst_ip: None,
                                    src_port: None,
                                    dst_port: None,
                                }
                            }
                        }
                    },
                },

                Err(_) => json::JsonPacket {
                    protocol: "Raw".to_string(),
                    length: len,
                    time: helpers::current_unix_secs()?,
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: None,
                },
            };

            println!("{}", serde_json::to_string(&json_packet)?);
            continue;
        }

        print!(
            "[{:>5}] {}.{:06} | Length: {:>5} bytes | ",
            packet_count, ts.tv_sec, ts.tv_usec, len
        );

        match SlicedPacket::from_ethernet(packet.data) {
            Ok(sliced) => match sliced.transport {
                Some(TransportSlice::Tcp(tcp)) => println!(
                    "TCP {}:{} -> {}:{}",
                    helpers::format_ip_src(&sliced.net),
                    tcp.source_port(),
                    helpers::format_ip_dst(&sliced.net),
                    tcp.destination_port()
                ),

                Some(TransportSlice::Udp(udp)) => println!(
                    "UDP {}:{} -> {}:{}",
                    helpers::format_ip_src(&sliced.net),
                    udp.source_port(),
                    helpers::format_ip_dst(&sliced.net),
                    udp.destination_port()
                ),

                Some(TransportSlice::Icmpv4(_)) => println!(
                    "ICMPv4 {} -> {}",
                    helpers::format_ip_src(&sliced.net),
                    helpers::format_ip_dst(&sliced.net)
                ),

                Some(TransportSlice::Icmpv6(_)) => println!(
                    "ICMPv6 {} -> {}",
                    helpers::format_ip_src(&sliced.net),
                    helpers::format_ip_dst(&sliced.net)
                ),

                Some(TransportSlice::Igmp(_)) => println!(
                    "IGMP {} -> {}",
                    helpers::format_ip_src(&sliced.net),
                    helpers::format_ip_dst(&sliced.net)
                ),

                None => match &sliced.net {
                    Some(NetSlice::Ipv4(ipv4)) => println!(
                        "IPv4 {} -> {}",
                        ipv4.header().source_addr(),
                        ipv4.header().destination_addr()
                    ),

                    Some(NetSlice::Ipv6(ipv6)) => println!(
                        "IPv6 {} -> {}",
                        ipv6.header().source_addr(),
                        ipv6.header().destination_addr()
                    ),

                    Some(NetSlice::Arp(_)) => println!("ARP"),
                    None => {
                        if let Some(LinkSlice::Ethernet2(eth)) = &sliced.link {
                            println!(
                                "Non-IP Ethernet Frame (EtherType: 0x{:04x}, Src: {}, Dst: {})",
                                eth.ether_type().0,
                                helpers::format_mac_address(&eth.source()),
                                helpers::format_mac_address(&eth.destination())
                            );

                            continue;
                        }

                        println!("Unknown Non-Ethernet Frame")
                    }
                },
            },

            Err(_) => println!("Raw frame (could not dissect Ethernet header)"),
        };

        if flags.show_package_bytes {
            println!("{}", helpers::format_data(packet.data, 8));
        }
    }

    Ok(())
}
