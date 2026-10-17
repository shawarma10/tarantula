pub mod capturing;
pub mod helpers;
pub mod flags;

use anyhow::bail;
use pcap::{Capture, Device};
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let flags = flags::Flags::parse();

    // Discover available network devices
    let devices = Device::list()?;
    if devices.is_empty() {
        bail!("No network interfaces found. Try running with root/admin privileges.");
    }

    if flags.show_available_devices {
        println!("Available network devices:");
        for (i, dev) in devices.iter().enumerate() {
            let desc = dev.desc.as_deref().unwrap_or("no description");
            println!("  [{}] {} ({})", i, dev.name, desc);
        }

        return Ok(());
    }

    // Select default capture device
    let default_device = match flags.device {
        Some(device) => match devices.get(device) {
            Some(d) => d.clone(),
            None => bail!("Invalid device index: {} (No such device)", device)
        }

        None => match Device::lookup()? {
            Some(dev) => dev,
            None => devices[0].clone(),
        }
    };

    println!("\nCapturing on device: '{}'...", default_device.name);

    // Configure the handle for capturing packets
    let mut cap = Capture::from_device(default_device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .immediate_mode(true)
        .open()?;

    cap.filter(&flags.filter_string, true)?;

    println!("Listening for packets (press Ctrl+C to stop)...");
    capturing::capture_loop(cap, &flags)
}
