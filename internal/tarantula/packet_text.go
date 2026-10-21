package tarantula

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func printPacket(count uint64, info gopacket.CaptureInfo, data []byte) bool {
	fmt.Fprintf(os.Stdout, "[%5d] %d.%06d | Length: %5d bytes | ", count, info.Timestamp.Unix(), info.Timestamp.Nanosecond()/1000, info.Length)
	packet, valid := decodeEthernet(data)
	if !valid {
		fmt.Fprintln(os.Stdout, "Raw frame (could not dissect Ethernet header)")
		return false
	}

	switch {
	case packet.Layer(layers.LayerTypeTCP) != nil:
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		address := networkAddresses(packet)
		fmt.Fprintf(os.Stdout, "TCP %s:%d -> %s:%d\n", *address.src, tcp.SrcPort, *address.dst, tcp.DstPort)

	case packet.Layer(layers.LayerTypeUDP) != nil:
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		address := networkAddresses(packet)
		fmt.Fprintf(os.Stdout, "UDP %s:%d -> %s:%d\n", *address.src, udp.SrcPort, *address.dst, udp.DstPort)

	case packet.Layer(layers.LayerTypeICMPv4) != nil:
		address := networkAddresses(packet)
		fmt.Fprintf(os.Stdout, "ICMPv4 %s -> %s\n", *address.src, *address.dst)

	case packet.Layer(layers.LayerTypeICMPv6) != nil:
		address := networkAddresses(packet)
		fmt.Fprintf(os.Stdout, "ICMPv6 %s -> %s\n", *address.src, *address.dst)

	case packet.Layer(layers.LayerTypeIGMP) != nil:
		address := networkAddresses(packet)
		fmt.Fprintf(os.Stdout, "IGMP %s -> %s\n", *address.src, *address.dst)

	case packet.Layer(layers.LayerTypeIPv4) != nil:
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		fmt.Fprintf(os.Stdout, "IPv4 %s -> %s\n", ip.SrcIP, ip.DstIP)

	case packet.Layer(layers.LayerTypeIPv6) != nil:
		ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		fmt.Fprintf(os.Stdout, "IPv6 %s -> %s\n", ip.SrcIP, ip.DstIP)

	case packet.Layer(layers.LayerTypeARP) != nil:
		fmt.Fprintln(os.Stdout, "ARP")

	case packet.Layer(layers.LayerTypeEthernet) != nil:
		eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		fmt.Fprintf(
			os.Stdout,
			"Non-IP Ethernet Frame (EtherType: 0x%04x, Src: %s, Dst: %s)\n",
			uint16(eth.EthernetType), eth.SrcMAC, eth.DstMAC,
		)

		return true

	default:
		fmt.Fprintln(os.Stdout, "Unknown Non-Ethernet Frame")
	}

	return false
}
