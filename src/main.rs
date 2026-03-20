use clap::Parser;
use tp1::{parse_pcap_file, save_output}; // assuming your crate name is tp1_lib

#[derive(clap::Parser, Debug)]
#[command(author, version, about = "Network packet analyzer")]
struct Args {
    /// PCAP file to analyze
    #[arg(long)]
    pcap: Option<String>,

    /// Network interface for live capture (incompatible with --pcap)
    #[arg(long, conflicts_with = "pcap")]
    interface: Option<String>,

    /// List available network interfaces and exit
    #[arg(long)]
    cards: bool,

    /// Capture filter (ex: "tcp port 80")
    #[arg(long)]
    filter: Option<String>,

    /// Number of packets to capture (default: 10)
    #[arg(long, default_value_t = 10)]
    packet_count: u32,

    /// Output format (JSON, CSV, etc.)
    #[arg(long, default_value = "json")]
    output_format: String,

    /// Output file name (if None, prints to terminal)
    #[arg(long, default_value = "results.json")]
    output_file: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let filename = args.pcap.as_ref().expect("No PCAP file provided");

    let output = parse_pcap_file(filename)?;
    save_output(&output, &args.output_format, Some(&args.output_file))?;

    Ok(())
}