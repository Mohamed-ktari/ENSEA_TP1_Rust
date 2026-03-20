use clap::Parser;

/// Packet Analyzer CLI
#[derive(Parser, Debug)]
#[command(author, version, about = "Network packet analyzer", long_about = None)]
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

    /// Output format (json, csv, etc.)
    #[arg(long, default_value = "json")]
    output_format: String,

    /// Output file name
    #[arg(long, default_value = "results.json")]
    output_file: String,
}

fn main() {
    let args = Args::parse();

    println!("{:#?}", args);

    // Example logic
    if args.cards {
        println!("Listing network interfaces...");
        // TODO: implement interface listing
        return;
    }

    if let Some(pcap_file) = args.pcap {
        println!("Analyzing PCAP file: {}", pcap_file);
    }

    if let Some(interface) = args.interface {
        println!("Capturing on interface: {}", interface);
    }

    println!("Packet count: {}", args.packet_count);
    println!("Output format: {}", args.output_format);
    println!("Output file: {}", args.output_file);

    if let Some(filter) = args.filter {
        println!("Using filter: {}", filter);
    }
}