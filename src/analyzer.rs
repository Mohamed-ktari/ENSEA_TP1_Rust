use crate::models::{BeaconInfo, DroneInfo, VendorSpecificInfo};
use pcap::Capture;

const BEACON_TYPE: u16 = 0;
const BEACON_SUBTYPE: u16 = 8;
const DJI_OUI: &str = "fa:0b:bc";

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

    if frame.len() < 24 + 12 {
        return None;
    }

    // Frame Control: first 2 bytes of 802.11 header
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type = (frame_control >> 2) & 0b11;
    let frame_subtype = (frame_control >> 4) & 0b1111;

    let is_beacon = frame_type == BEACON_TYPE && frame_subtype == BEACON_SUBTYPE;
    if !is_beacon {
        return None;
    }

    // Source MAC = addr2
    let source_mac = format_mac(&frame[10..16]);

    // Tagged parameters after 24-byte MAC header + 12-byte fixed params
    let tags = &frame[24 + 12..];

    let ssid = extract_ssid(tags).unwrap_or_else(|| "<hidden>".to_string());
    let vendor_specific = extract_vendor_specific_tags(tags);
    let has_vendor_specific = !vendor_specific.is_empty();

    let has_dji_oui = vendor_specific.iter().any(|v| v.oui == DJI_OUI);

    let is_drone_id = is_beacon && has_vendor_specific && has_dji_oui;

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

            if oui == DJI_OUI {
                // Heuristique simplifiée.
                // Les offsets peuvent varier selon le format exact.
                let drone_id = Some(ssid.to_string());

                let latitude = if value.len() >= 9 {
                    Some(i32::from_le_bytes([value[5], value[6], value[7], value[8]]) as f64 / 1e7)
                } else {
                    None
                };

                let longitude = if value.len() >= 13 {
                    Some(i32::from_le_bytes([value[9], value[10], value[11], value[12]]) as f64 / 1e7)
                } else {
                    None
                };

                let altitude = if value.len() >= 15 {
                    Some(i16::from_le_bytes([value[13], value[14]]) as f32 / 10.0)
                } else {
                    None
                };

                let speed = if value.len() >= 17 {
                    Some(i16::from_le_bytes([value[15], value[16]]) as f32 / 10.0)
                } else {
                    None
                };

                return Some(DroneInfo {
                    drone_id,
                    latitude,
                    longitude,
                    altitude,
                    speed,
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

            result.push(VendorSpecificInfo {
                oui,
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