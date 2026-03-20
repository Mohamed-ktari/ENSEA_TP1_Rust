use clap::Parser;
use serde::Serialize;
use std::fs::File;
use std::io::{self, Write};

/// Packet Analyzer CLI
#[derive(Parser, Debug, Serialize)]
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

    /// Output format 
    #[arg(long, default_value = "json")]
    output_format: String,

    /// Output file name (if None, prints to terminal)
    #[arg(long)]
    output_file: Option<String>,
}

// Structure pour contenir le rapport final
#[derive(Serialize)]
struct Report<'a> {
    args: &'a Args,
    messages: Vec<String>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let mut messages: Vec<String> = Vec::new();

    // Exemple de logique
    if args.cards {
        messages.push("Listing network interfaces...".to_string());
        // TODO: implement interface listing
    }

    if let Some(pcap_file) = &args.pcap {
        messages.push(format!("Analyzing PCAP file: {}", pcap_file));
    }

    if let Some(interface) = &args.interface {
        messages.push(format!("Capturing on interface: {}", interface));
    }

    messages.push(format!("Packet count: {}", args.packet_count));
    messages.push(format!("Output format: {}", args.output_format));

    if let Some(filter) = &args.filter {
        messages.push(format!("Using filter: {}", filter));
    }

    let report = Report {
        args: &args,
        messages,
    };

    
    if let Some(ref file_name) = args.output_file {
        let file = File::create(file_name)?;
        serde_json::to_writer_pretty(file, &report)?;
    } else {
        let stdout = io::stdout();
        let handle = stdout.lock();
        serde_json::to_writer_pretty(handle, &report)?;
    }

    Ok(())
}