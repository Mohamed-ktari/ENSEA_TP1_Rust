use clap::Parser;
use serde::Serialize;
use std::fs::File;
use std::io::{self, Write};
use pcap::Capture;



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


#[derive(Serialize, Debug)]
struct BeaconFrame {
    ssid: String,
    mac: String,
    channel: Option<u8>,
    signal_dbm: Option<i8>,
    rates: Vec<f32>,
}

#[derive(Serialize, Debug)]
struct DroneIDFrame {
    drone_id : String,
    mac: String,
    vendor: String,
    raw_data: String,

}

#[derive(Serialize)]
struct Output {
    beacons: Vec<BeaconFrame>,
    drones: Vec<DroneIDFrame>,
}

fn parse_beacon(
    data: &[u8],
    mac_src: &str,
    signal_dbm: Option<i8>,
) -> Option<(BeaconFrame, Option<DroneIDFrame>)> {

    let mut offset = 12;
    let mut ssid = String::new();
    let mut drone: Option<DroneIDFrame> = None;
    let mut rates: Vec<f32> = Vec::new();
    let mut channel: Option<u8> = None;

    
    let drone_ouis: [[u8; 3]; 1] = [
        [0x8c, 0xfd, 0xf0],
    ];

    while offset + 2 <= data.len() {
        let tlv_type = data[offset];
        let tlv_len = data[offset + 1] as usize;

        if offset + 2 + tlv_len > data.len() {
            break;
        }

        let tlv_value = &data[offset + 2..offset + 2 + tlv_len];

        match tlv_type {
            0x00 => { 
                if !tlv_value.is_empty() {
                    ssid = String::from_utf8_lossy(tlv_value).to_string();
                }
            }

            0x01 => { 
                rates = tlv_value.iter()
                    .map(|r| (r & 0x7F) as f32 * 0.5)
                    .collect();
            }

            0x03 => { // DS Parameter Set (Channel)
                if !tlv_value.is_empty() {
                    channel = Some(tlv_value[0]);
                }
            }

            0xdd => { // Vendor Specific → possible DroneID
                if tlv_value.len() >= 3 {
                    let vendor_bytes = &tlv_value[0..3];

                    // Check if vendor OUI matches known drone manufacturers
                    let is_drone = drone_ouis.iter().any(|oui| oui == vendor_bytes);

                    if is_drone {
                        // DroneID payload is the rest of the TLV after the OUI
                        let payload = &tlv_value[3..];

                        // For simplicity, we store DroneID as hex string of first few bytes
                        let drone_id = if payload.len() >= 4 {
                            payload[0..4].iter().map(|b| format!("{:02x}", b)).collect::<String>()
                        } else {
                            payload.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                        };

                        let raw_data = payload.iter().map(|b| format!("{:02x}", b)).collect::<String>();

                        let vendor = vendor_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");

                        drone = Some(DroneIDFrame {
                            drone_id: drone_id,
                            mac: mac_src.to_string(),
                            vendor,
                            raw_data,
                        });
                    }
                }
            }

            _ => {}
        }

        offset += 2 + tlv_len;
    }

    Some((
        BeaconFrame {
            ssid,
            mac: mac_src.to_string(),
            channel,
            signal_dbm,
            rates,
        },
        drone,
    ))
}


fn save_output(
    output: &Output,
    format: &str,
    filename: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match format.to_lowercase().as_str() {
        "json" => {
            if let Some(file_name) = filename {
                let file = File::create(file_name)?;
                serde_json::to_writer_pretty(file, output)?;
            } else {
                let stdout = io::stdout();
                let handle = stdout.lock();
                serde_json::to_writer_pretty(handle, output)?;
            }
        }

        "csv" => {
            let writer: Box<dyn Write> = if let Some(file_name) = filename {
                Box::new(File::create(file_name)?)
            } else {
                Box::new(io::stdout())
            };

            let mut wtr = csv::Writer::from_writer(writer);

            // Serialize beacons
            for beacon in &output.beacons {
                wtr.write_record(&[
                    &beacon.ssid,
                    &beacon.mac,
                    &beacon.channel.unwrap_or(0).to_string(),
                    &beacon.signal_dbm.unwrap_or(0).to_string(),
                    &beacon.rates.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(","),
                    "", "", "", "", // empty columns for drone fields
                ])?;
            }

            for drone in &output.drones {
                wtr.write_record(&[
                    "", "", "", "", "",  // empty columns for beacon fields
                    &drone.drone_id,
                    &drone.mac,
                    &drone.vendor,
                    &drone.raw_data,
                ])?;
            }

            wtr.flush()?;
        }

        _ => return Err(format!("Unsupported output format: {}", format).into()),
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    let args = Args::parse();
    let filename = args.pcap.as_ref().expect("No PCAP file provided");
    let mut cap = Capture::from_file(filename)?;

    let mut beacons: Vec<BeaconFrame> = Vec::new();
    let mut drones: Vec<DroneIDFrame> = Vec::new();

    while let Ok(packet) = cap.next_packet() {
            let data = packet.data;

            if data.len() < 4 {
                continue;
            }

            let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;

            if data.len() <= radiotap_len + 24 {
                continue;
            }

            let signal_dbm = if radiotap_len >= 2 {
                Some(data[radiotap_len - 2] as i8)
            } else {
                None
            };

            let mac_header = &data[radiotap_len..radiotap_len + 24];

            let mac_src = mac_header[10..16].iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");

            let frame_control = u16::from_le_bytes([mac_header[0], mac_header[1]]);
            let frame_type = (frame_control >> 2) & 0b11;
            let frame_subtype = (frame_control >> 4) & 0b1111;

            if frame_type == 0 && frame_subtype == 8 {
                if let Some(beacon) = parse_beacon(
                    &data[radiotap_len + 24..],
                    &mac_src,
                    signal_dbm,
                ) {
                    beacons.push(beacon.0);
                    if let Some(drone) = beacon.1 {
                        drones.push(drone);
                    }
                }
            }
        }
    let output = Output { beacons, drones };

    save_output(&output, &args.output_format, args.output_file.as_deref())?;

    Ok(())
}