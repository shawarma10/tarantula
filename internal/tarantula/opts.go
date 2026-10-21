package tarantula

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
)

type options struct {
	filter               string
	showPackageBytes     bool
	device               int
	deviceSet            bool
	showAvailableDevices bool
	json                 bool
	help                 bool
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("tarantula", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tarantula [OPTIONS]")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		fmt.Fprintln(os.Stderr, "  -f, --filter-string <FILTER_STRING>  Filter string to apply to packets (BPF syntax)")
		fmt.Fprintln(os.Stderr, "  -b, --show-package-bytes             Show packet bytes as hex-represented numbers")
		fmt.Fprintln(os.Stderr, "  -d, --device <DEVICE>                Use a specific capture device index")
		fmt.Fprintln(os.Stderr, "  -a, --show-available-devices         Show available capture devices")
		fmt.Fprintln(os.Stderr, "  -j, --json                           Output packet information as JSON")
		fmt.Fprintln(os.Stderr, "  -h, --help                           Print help")
	}

	flags.StringVar(&opts.filter, "f", "", "Filter string to apply to packets (BPF syntax)")
	flags.StringVar(&opts.filter, "filter-string", "", "Filter string to apply to packets (BPF syntax)")
	flags.BoolVar(&opts.showPackageBytes, "b", false, "Show packet bytes as hex-represented numbers")
	flags.BoolVar(&opts.showPackageBytes, "show-package-bytes", false, "Show packet bytes as hex-represented numbers")
	flags.IntVar(&opts.device, "d", 0, "Use a specific capture device index")
	flags.IntVar(&opts.device, "device", 0, "Use a specific capture device index")
	flags.BoolVar(&opts.showAvailableDevices, "a", false, "Show available capture devices")
	flags.BoolVar(&opts.showAvailableDevices, "show-available-devices", false, "Show available capture devices")
	flags.BoolVar(&opts.json, "j", false, "Output packet information as JSON")
	flags.BoolVar(&opts.json, "json", false, "Output packet information as JSON")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.help = true
			return opts, nil
		}

		return opts, err
	}

	if flags.NArg() != 0 {
		return opts, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	flags.Visit(func(f *flag.Flag) {
		if f.Name == "d" || f.Name == "device" {
			opts.deviceSet = true
		}
	})

	if opts.device < 0 {
		return opts, fmt.Errorf("invalid value %q for --device: expected a non-negative index", strconv.Itoa(opts.device))
	}

	return opts, nil
}
