package tarantula

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type addresses struct {
	src *string
	dst *string
}

func networkAddresses(packet gopacket.Packet) addresses {
	switch {
	case packet.Layer(layers.LayerTypeIPv4) != nil:
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		return addresses{new(ip.SrcIP.String()), new(ip.DstIP.String())}

	case packet.Layer(layers.LayerTypeIPv6) != nil:
		ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		return addresses{new(ip.SrcIP.String()), new(ip.DstIP.String())}

	default:
		return addresses{new("unknown"), new("unknown")}
	}
}

func decodeEthernet(data []byte) (gopacket.Packet, bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.Layer(layers.LayerTypeEthernet) == nil || packet.ErrorLayer() != nil {
		return packet, false
	}

	return packet, true
}
