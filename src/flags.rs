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
}
