use crate::models::{BeaconInfo, DroneInfo, VendorSpecificInfo};
//use pcap::{Capture, Device};
use pcap::Capture;

const BEACON_TYPE: u16 = 0;
const BEACON_SUBTYPE: u16 = 8;
/* 
pub fn list_interfaces() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let devices = Device::list()?;
    Ok(devices.into_iter().map(|d| d.name).collect())
}*/

pub fn analyze_pcap(
    pcap_file: &str,
) -> Result<(Vec<String>, Vec<BeaconInfo>), Box<dyn std::error::Error>> {
    let mut messages = Vec::new();
    let mut beacons = Vec::new();

    messages.push(format!("Analyzing PCAP file: {}", pcap_file));

    let mut cap = Capture::from_file(pcap_file)?;
    let mut packet_number = 0usize;

    while let Ok(packet) = cap.next_packet() {
        packet_number += 1;

        if let Some(beacon) = parse_beacon(packet_number, packet.data) {
            beacons.push(beacon);
        }
    }

    messages.push(format!("Beacon frames found: {}", beacons.len()));

    let drone_count = beacons.iter().filter(|b| b.is_drone_id).count();
    messages.push(format!("DroneID beacons found: {}", drone_count));

    Ok((messages, beacons))
}
/* 
pub fn capture_live(
    interface_name: &str,
    filter: Option<&str>,
    packet_count: u32,
) -> Result<(Vec<String>, Vec<BeaconInfo>), Box<dyn std::error::Error>> {
    let mut messages = Vec::new();
    let mut beacons = Vec::new();

    messages.push(format!("Capturing live on interface: {}", interface_name));

    let default_filter = "wlan type mgt subtype beacon";
    let capture_filter = filter.unwrap_or(default_filter);
    messages.push(format!("Using capture filter: {}", capture_filter));

    let mut cap = Capture::from_device(interface_name)?
        .promisc(true)
        .immediate_mode(true)
        .open()?;

    cap.filter(capture_filter, true)?;

    let mut packet_number = 0usize;

    while packet_number < packet_count as usize {
        match cap.next_packet() {
            Ok(packet) => {
                packet_number += 1;

                if let Some(beacon) = parse_beacon(packet_number, packet.data) {
                    println!(
                        "[{}] MAC={} SSID={} DroneID={}",
                        beacon.packet_number,
                        beacon.source_mac,
                        beacon.ssid,
                        beacon.is_drone_id
                    );
                    beacons.push(beacon);
                }
            }
            Err(e) => {
                messages.push(format!("Capture error: {}", e));
                break;
            }
        }
    }

    messages.push(format!("Captured beacon frames: {}", beacons.len()));

    let drone_count = beacons.iter().filter(|b| b.is_drone_id).count();
    messages.push(format!("DroneID beacons found: {}", drone_count));

    Ok((messages, beacons))
}
*/
fn parse_beacon(packet_number: usize, data: &[u8]) -> Option<BeaconInfo> {
    if data.len() < 4 {
        return None;
    }

    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;

    if data.len() < radiotap_len + 24 + 12 {
        return None;
    }

    let frame = &data[radiotap_len..];

    if frame.len() < 24 + 12 {
        return None;
    }

    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type = (frame_control >> 2) & 0b11;
    let frame_subtype = (frame_control >> 4) & 0b1111;

    let is_beacon = frame_type == BEACON_TYPE && frame_subtype == BEACON_SUBTYPE;
    if !is_beacon {
        return None;
    }

    let source_mac = format_mac(&frame[10..16]);
    let tags = &frame[24 + 12..];

    let ssid = extract_ssid(tags).unwrap_or_else(|| "<hidden>".to_string());
    let vendor_specific = extract_vendor_specific_tags(tags);
    let has_vendor_specific = !vendor_specific.is_empty();

    let is_drone_id = is_beacon
        && has_vendor_specific
        && vendor_specific.iter().any(|v| {
            (v.oui == "fa:0b:bc" && v.vendor_type == Some(13))
                || (v.oui == "6a:5c:35" && v.vendor_type == Some(1))
        });

    let drone_info = if is_drone_id {
        extract_drone_info(tags, &ssid)
    } else {
        None
    };

    Some(BeaconInfo {
        packet_number,
        source_mac,
        ssid,
        has_vendor_specific,
        is_drone_id,
        vendor_specific,
        drone_info,
    })
}

fn extract_drone_info(tags: &[u8], ssid: &str) -> Option<DroneInfo> {
    let mut i = 0usize;

    while i + 2 <= tags.len() {
        let tag_type = tags[i];
        let tag_len = tags[i + 1] as usize;
        i += 2;

        if i + tag_len > tags.len() {
            return None;
        }

        let value = &tags[i..i + tag_len];

        if tag_type == 0xdd {
            let oui = if value.len() >= 3 {
                format!("{:02x}:{:02x}:{:02x}", value[0], value[1], value[2])
            } else {
                String::new()
            };

            let vendor_type = if value.len() >= 4 { Some(value[3]) } else { None };

            if (oui == "fa:0b:bc" && vendor_type == Some(13))
                || (oui == "6a:5c:35" && vendor_type == Some(1))
            {
                return Some(DroneInfo {
                    drone_id: Some(ssid.to_string()),
                    latitude: None,
                    longitude: None,
                    altitude: None,
                    speed: None,
                });
            }
        }

        i += tag_len;
    }

    None
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
    let mut result = Vec::new();

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

            let vendor_type = if value.len() >= 4 { Some(value[3]) } else { None };

            result.push(VendorSpecificInfo {
                oui,
                vendor_type,
                data_hex: bytes_to_hex(value),
                length: tag_len,
            });
        }

        i += tag_len;
    }

    result
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