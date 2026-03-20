
//use tp1::analyzer::{analyze_pcap, capture_live, list_interfaces};
use clap::Parser;
use tp1::analyzer::analyze_pcap;
use tp1::models::{Args, Report};
use tp1::output::save_report;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut messages = Vec::new();
    let mut beacons = Vec::new();

    if let Some(filter) = &args.filter {
        messages.push(format!("Using filter: {}", filter));
    }

    messages.push(format!("Packet count option: {}", args.packet_count));
    messages.push(format!("Output format: {}", args.output_format));

    if args.cards {
        messages.push("Partie 6 désactivée.".to_string());
    }

    if let Some(interface) = &args.interface {
        messages.push(format!(
            "Live capture disabled. Interface requested: {}",
            interface
        ));
    }

    if let Some(pcap_file) = &args.pcap {
        let (analyzer_messages, analyzer_beacons) = analyze_pcap(pcap_file)?;
        messages.extend(analyzer_messages);
        beacons = analyzer_beacons;
    } else {
        messages.push("No PCAP file provided.".to_string());
    }

    let report = Report {
        args: &args,
        messages,
        beacons,
    };

    save_report(&report, &args.output_format, args.output_file.as_deref())?;

    Ok(())
}
/*
    } else if let Some(interface) = &args.interface {
        let (capture_messages, capture_beacons) =
            capture_live(interface, args.filter.as_deref(), args.packet_count)?;
        messages.extend(capture_messages);
        beacons = capture_beacons;
    }  */