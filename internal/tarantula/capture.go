package tarantula

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket/pcap"
)

const snapshotLength = 65535

func Run(args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}

	if opts.help {
		return nil
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("list network devices: %w", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("no network interfaces found. Try running with root/admin privileges")
	}

	if opts.showAvailableDevices {
		fmt.Fprintln(os.Stdout, "Available network devices:")
		for i, dev := range devices {
			desc := dev.Description
			if desc == "" {
				desc = "no description"
			}

			fmt.Fprintf(os.Stdout, "  [%d] %s (%s)\n", i, dev.Name, desc)
		}

		return nil
	}

	device, err := selectDevice(devices, opts)
	if err != nil {
		return err
	}

	if !opts.json {
		fmt.Fprintf(os.Stdout, "\nCapturing on device: '%s'...\n", device.Name)
	}

	inactive, err := pcap.NewInactiveHandle(device.Name)
	if err != nil {
		return fmt.Errorf("configure capture on %q: %w", device.Name, err)
	}

	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(snapshotLength); err != nil {
		return fmt.Errorf("set snapshot length: %w", err)
	}

	if err := inactive.SetPromisc(true); err != nil {
		return fmt.Errorf("enable promiscuous mode: %w", err)
	}

	if err := inactive.SetTimeout(time.Second); err != nil {
		return fmt.Errorf("set capture timeout: %w", err)
	}

	if err := inactive.SetImmediateMode(true); err != nil {
		return fmt.Errorf("enable immediate mode: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return fmt.Errorf("open capture device %q: %w", device.Name, err)
	}

	defer handle.Close()
	if err := handle.SetBPFFilter(opts.filter); err != nil {
		return fmt.Errorf("apply BPF filter: %w", err)
	}

	if !opts.json {
		fmt.Fprintln(os.Stdout, "Listening for packets (press Ctrl+C to stop)...")
	}

	running := true
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		running = false
	}()

	return capturePackets(context.Background(), handle, opts, &running)
}

func capturePackets(ctx context.Context, handle *pcap.Handle, opts options, running *bool) error {
	var packetCount uint64
	encoder := json.NewEncoder(os.Stdout)

	for *running {
		data, captureInfo, err := handle.ReadPacketData()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			if err == pcap.NextErrorTimeoutExpired {
				continue
			}

			return fmt.Errorf("read captured packet: %w", err)
		}

		packetCount++
		if opts.json {
			if err := encoder.Encode(decodeJSONPacket(data, captureInfo.Length)); err != nil {
				return fmt.Errorf("write packet JSON: %w", err)
			}

			continue
		}

		skipBytes := printPacket(packetCount, captureInfo, data)
		if opts.showPackageBytes && !skipBytes {
			fmt.Fprint(os.Stdout, formatData(data, 8))
		}
	}

	return nil
}
