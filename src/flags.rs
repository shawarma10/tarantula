use clap::Parser;

#[derive(Debug, Parser)]
pub struct Flags {
    /// Filter string to apply to packets.
    /// Uses BPF syntax
    #[arg(short, long, default_value_t = String::new())]
    pub filter_string: String,

    /// Show package bytes as hex-represented numbers
    #[arg(short, long, default_value_t = false)]
    pub show_package_bytes: bool,

    /// Uses a specific device for connection capturing.
    /// Find available devices with the `-a` flag
    #[arg(short = 'd', long)]
    pub device: Option<usize>,

    /// Only shows available devices for connection capturing
    #[arg(short = 'a', long, default_value_t = false)]
    pub show_available_devices: bool,

    /// Output packet information as JSON
    #[arg(short = 'j', long, default_value_t = false)]
    pub json: bool,
}
