use clap::Parser;
use pcap::Capture;
use serde::Serialize;
use std::fs::File;
use std::io;

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

    /// Capture filter
    #[arg(long)]
    filter: Option<String>,

    /// Number of packets to capture (default: 10)
    #[arg(long, default_value_t = 10)]
    packet_count: u32,

    /// Output format
    #[arg(long, default_value = "json")]
    output_format: String,

    /// Output file name
    #[arg(long)]
    output_file: Option<String>,
}

#[derive(Debug, Serialize)]
struct VendorSpecificInfo {
    oui: String,
    data_hex: String,
    length: usize,
}

#[derive(Debug, Serialize)]
struct BeaconInfo {
    packet_number: usize,
    source_mac: String,
    destination_mac: String,
    bssid: String,
    ssid: String,
    beacon_interval: u16,
    has_vendor_specific: bool,
    is_drone_id: bool,
    vendor_specific: Vec<VendorSpecificInfo>,
}

#[derive(Serialize)]
struct Report<'a> {
    args: &'a Args,
    messages: Vec<String>,
    beacons: Vec<BeaconInfo>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut messages: Vec<String> = Vec::new();
    let mut beacons: Vec<BeaconInfo> = Vec::new();

    if args.cards {
        messages.push("Listing network interfaces...".to_string());
        // Partie 6 plus tard
    }

    if let Some(interface) = &args.interface {
        messages.push(format!("Capturing on interface: {}", interface));
        // Partie 6 plus tard
    }

    if let Some(filter) = &args.filter {
        messages.push(format!("Using filter: {}", filter));
    }

    messages.push(format!("Packet count option: {}", args.packet_count));
    messages.push(format!("Output format: {}", args.output_format));

    if let Some(pcap_file) = &args.pcap {
        messages.push(format!("Analyzing PCAP file: {}", pcap_file));

        let mut cap = Capture::from_file(pcap_file)?;
        let mut packet_number: usize = 0;

        while let Ok(packet) = cap.next_packet() {
            packet_number += 1;

            if let Some(beacon) = parse_beacon(packet_number, packet.data) {
                beacons.push(beacon);
            }
        }

        messages.push(format!("Beacon frames found: {}", beacons.len()));

        let drone_count = beacons.iter().filter(|b| b.is_drone_id).count();
        messages.push(format!("Possible DroneID beacons found: {}", drone_count));
    }

    let report = Report {
        args: &args,
        messages,
        beacons,
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

fn parse_beacon(packet_number: usize, data: &[u8]) -> Option<BeaconInfo> {
    if data.len() < 4 {
        return None;
    }

    // Radiotap length: bytes 2 and 3, little-endian
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;

    if data.len() < radiotap_len + 24 + 12 {
        return None;
    }

    let frame = &data[radiotap_len..];

    if frame.len() < 24 {
        return None;
    }

    // Frame Control
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type = (frame_control >> 2) & 0b11;
    let frame_subtype = (frame_control >> 4) & 0b1111;

    // Beacon = type 0, subtype 8
    if frame_type != 0 || frame_subtype != 8 {
        return None;
    }

    // Standard 802.11 beacon:
    // 24 bytes MAC header + 12 bytes fixed parameters + tagged parameters
    if frame.len() < 24 + 12 {
        return None;
    }

    let destination_mac = format_mac(&frame[4..10]);
    let source_mac = format_mac(&frame[10..16]);
    let bssid = format_mac(&frame[16..22]);

    // Fixed parameters start just after the 24-byte MAC header
    let fixed_params = &frame[24..24 + 12];

    // Beacon interval = bytes 8..10 in fixed parameters
    let beacon_interval = u16::from_le_bytes([fixed_params[8], fixed_params[9]]);

    // Tagged parameters (TLV)
    let tags = &frame[24 + 12..];

    let ssid = extract_ssid(tags).unwrap_or_else(|| "<hidden>".to_string());
    let vendor_specific = extract_vendor_specific_tags(tags);
    let has_vendor_specific = !vendor_specific.is_empty();

    let is_drone_id = ssid.starts_with("RID-") || has_vendor_specific;

    Some(BeaconInfo {
        packet_number,
        source_mac,
        destination_mac,
        bssid,
        ssid,
        beacon_interval,
        has_vendor_specific,
        is_drone_id,
        vendor_specific,
    })
}

fn extract_ssid(tags: &[u8]) -> Option<String> {
    let mut i = 0usize;

    while i + 2 <= tags.len() {
        let tag_type = tags[i];
        let tag_len = tags[i + 1] as usize;
        i += 2;

        if i + tag_len > tags.len() {
            return None;
        }

        let value = &tags[i..i + tag_len];

        if tag_type == 0x00 {
            return Some(String::from_utf8_lossy(value).to_string());
        }

        i += tag_len;
    }

    None
}

fn extract_vendor_specific_tags(tags: &[u8]) -> Vec<VendorSpecificInfo> {
    let mut i = 0usize;
    let mut vendors = Vec::new();

    while i + 2 <= tags.len() {
        let tag_type = tags[i];
        let tag_len = tags[i + 1] as usize;
        i += 2;

        if i + tag_len > tags.len() {
            break;
        }

        let value = &tags[i..i + tag_len];

        if tag_type == 0xdd {
            let oui = if value.len() >= 3 {
                format!("{:02x}:{:02x}:{:02x}", value[0], value[1], value[2])
            } else {
                "<unknown>".to_string()
            };

            let data_hex = bytes_to_hex(value);

            vendors.push(VendorSpecificInfo {
                oui,
                data_hex,
                length: tag_len,
            });
        }

        i += tag_len;
    }

    vendors
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}