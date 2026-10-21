package tarantula

import (
	"time"

	"github.com/google/gopacket/layers"
)

type jsonPacket struct {
	Protocol string  `json:"protocol"`
	Length   uint32  `json:"length"`
	Time     uint64  `json:"time"`
	SrcIP    *string `json:"src_ip"`
	DstIP    *string `json:"dst_ip"`
	SrcPort  *uint16 `json:"src_port"`
	DstPort  *uint16 `json:"dst_port"`
}

func decodeJSONPacket(data []byte, length int) jsonPacket {
	packet, valid := decodeEthernet(data)
	if !valid {
		return jsonPacket{Protocol: "Raw", Length: uint32(length), Time: uint64(time.Now().Unix())}
	}

	result := jsonPacket{Length: uint32(length), Time: uint64(time.Now().Unix())}
	network := networkAddresses(packet)
	switch {
	case packet.Layer(layers.LayerTypeTCP) != nil:
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		result.Protocol, result.SrcIP, result.DstIP = "TCP", network.src, network.dst
		result.SrcPort, result.DstPort = new(uint16(tcp.SrcPort)), new(uint16(tcp.DstPort))

	case packet.Layer(layers.LayerTypeUDP) != nil:
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		result.Protocol, result.SrcIP, result.DstIP = "UDP", network.src, network.dst
		result.SrcPort, result.DstPort = new(uint16(udp.SrcPort)), new(uint16(udp.DstPort))

	case packet.Layer(layers.LayerTypeICMPv4) != nil:
		result.Protocol, result.SrcIP, result.DstIP = "ICMPv4", network.src, network.dst

	case packet.Layer(layers.LayerTypeICMPv6) != nil:
		result.Protocol, result.SrcIP, result.DstIP = "ICMPv6", network.src, network.dst

	case packet.Layer(layers.LayerTypeIGMP) != nil:
		result.Protocol, result.SrcIP, result.DstIP = "IGMP", network.src, network.dst

	case packet.Layer(layers.LayerTypeIPv4) != nil:
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		result.Protocol = "IPv4"
		result.SrcIP, result.DstIP = new(ip.SrcIP.String()), new(ip.DstIP.String())

	case packet.Layer(layers.LayerTypeIPv6) != nil:
		ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		result.Protocol = "IPv6"
		result.SrcIP, result.DstIP = new(ip.SrcIP.String()), new(ip.DstIP.String())

	case packet.Layer(layers.LayerTypeARP) != nil:
		result.Protocol = "ARP"

	case packet.Layer(layers.LayerTypeEthernet) != nil:
		result.Protocol = "Ethernet"

	default:
		result.Protocol = "Unknown"
	}

	return result
}
