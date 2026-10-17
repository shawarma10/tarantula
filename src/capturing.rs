use crate::helpers;
use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};
use pcap::{Active, Capture};

pub fn capture_loop(mut cap: Capture<Active>) -> anyhow::Result<()> {
    let mut packet_count = 0;

    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        let ts = packet.header.ts;
        let len = packet.header.len;

        print!(
            "[{:>5}] {}.{:06} | Length: {:>5} bytes | ",
            packet_count, ts.tv_sec, ts.tv_usec, len
        );

        match SlicedPacket::from_ethernet(packet.data) {
            Ok(sliced) => match sliced.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    println!(
                        "TCP {}:{} -> {}:{}",
                        helpers::format_ip_src(&sliced.net),
                        tcp.source_port(),
                        helpers::format_ip_dst(&sliced.net),
                        tcp.destination_port()
                    )
                }

                Some(TransportSlice::Udp(udp)) => {
                    println!(
                        "UDP {}:{} -> {}:{}",
                        helpers::format_ip_src(&sliced.net),
                        udp.source_port(),
                        helpers::format_ip_dst(&sliced.net),
                        udp.destination_port()
                    )
                }

                Some(TransportSlice::Icmpv4(_)) => {
                    println!(
                        "ICMPv4 {} -> {}",
                        helpers::format_ip_src(&sliced.net),
                        helpers::format_ip_dst(&sliced.net)
                    )
                }

                Some(TransportSlice::Icmpv6(_)) => {
                    println!(
                        "ICMPv6 {} -> {}",
                        helpers::format_ip_src(&sliced.net),
                        helpers::format_ip_dst(&sliced.net)
                    )
                }

                Some(TransportSlice::Igmp(_)) => {
                    println!(
                        "IGMP {} -> {}",
                        helpers::format_ip_src(&sliced.net),
                        helpers::format_ip_dst(&sliced.net)
                    )
                }

                None => match &sliced.net {
                    Some(NetSlice::Ipv4(ipv4)) => {
                        println!(
                            "IPv4 {} -> {}",
                            ipv4.header().source_addr(),
                            ipv4.header().destination_addr()
                        )
                    }

                    Some(NetSlice::Ipv6(ipv6)) => {
                        println!(
                            "IPv6 {} -> {}",
                            ipv6.header().source_addr(),
                            ipv6.header().destination_addr()
                        )
                    }

                    Some(NetSlice::Arp(_)) => println!("ARP"),
                    None => {
                        if let Some(LinkSlice::Ethernet2(eth)) = &sliced.link {
                            println!(
                                "Non-IP Ethernet Frame (EtherType: 0x{:04x}, Src: 0x{}, Dst: 0x{})",
                                eth.ether_type().0,
                                helpers::format_mac_address(&eth.source()),
                                helpers::format_mac_address(&eth.destination())
                            )
                        } else {
                            println!("Unknown Non-Ethernet Frame")
                        }
                    }
                },
            },

            Err(_) => println!("Raw frame (could not dissect Ethernet header)"),
        };
    }

    Ok(())
}
