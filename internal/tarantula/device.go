package tarantula

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket/pcap"
)

func selectDevice(devices []pcap.Interface, opts options) (pcap.Interface, error) {
	if opts.deviceSet {
		if opts.device >= len(devices) {
			return pcap.Interface{}, fmt.Errorf("invalid device index: %d (No such device)", opts.device)
		}

		return devices[opts.device], nil
	}

	defaultName, err := defaultDeviceName()
	if err == nil {
		for _, device := range devices {
			if device.Name == defaultName {
				return device, nil
			}
		}
	}

	return devices[0], nil
}

func defaultDeviceName() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	// The interface with the default IPv4 route is listed in procfs on Linux.
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[1] == "00000000" {
			for _, iface := range interfaces {
				if iface.Name == fields[0] {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("default network interface not found")
}
