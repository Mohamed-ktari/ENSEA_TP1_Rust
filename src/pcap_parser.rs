use pcap::Capture;

#[derive(serde::Serialize, Debug)]
pub struct BeaconFrame {
    pub ssid: String,
    pub mac: String,
    pub channel: Option<u8>,
    pub signal_dbm: Option<i8>,
    pub rates: Vec<f32>,
}

#[derive(serde::Serialize, Debug)]
pub struct DroneIDFrame {
    pub drone_id: String,
    pub mac: String,
    pub vendor: String,
    pub raw_data: String,
}

#[derive(serde::Serialize)]
pub struct Output {
    pub beacons: Vec<BeaconFrame>,
    pub drones: Vec<DroneIDFrame>,
}

/// Parse the beacon frame and return beacon + optional drone
pub fn parse_beacon(
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


/// Parse a PCAP file and extract beacons and drones
pub fn parse_pcap_file(filename: &str) -> Result<Output, Box<dyn std::error::Error>> {
    let mut cap = Capture::from_file(filename)?;
    let mut beacons: Vec<BeaconFrame> = Vec::new();
    let mut drones: Vec<DroneIDFrame> = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        if data.len() < 4 { continue; }

        let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        if data.len() <= radiotap_len + 24 { continue; }

        let signal_dbm = if radiotap_len >= 2 { Some(data[radiotap_len - 2] as i8) } else { None };
        let mac_header = &data[radiotap_len..radiotap_len + 24];
        let mac_src = mac_header[10..16].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");

        let frame_control = u16::from_le_bytes([mac_header[0], mac_header[1]]);
        let frame_type = (frame_control >> 2) & 0b11;
        let frame_subtype = (frame_control >> 4) & 0b1111;

        if frame_type == 0 && frame_subtype == 8 {
            if let Some(beacon) = parse_beacon(&data[radiotap_len + 24..], &mac_src, signal_dbm) {
                beacons.push(beacon.0);
                if let Some(drone) = beacon.1 { drones.push(drone); }
            }
        }
    }

    Ok(Output { beacons, drones })
}