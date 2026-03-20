use clap::Parser;
use serde::Serialize;

#[derive(Parser, Debug, Serialize)]
#[command(author, version, about = "Network packet analyzer", long_about = None)]
pub struct Args {
    #[arg(long)]
    pub pcap: Option<String>,

    #[arg(long, conflicts_with = "pcap")]
    pub interface: Option<String>,

    #[arg(long)]
    pub cards: bool,

    #[arg(long)]
    pub filter: Option<String>,

    #[arg(long, default_value_t = 10)]
    pub packet_count: u32,

    #[arg(long, default_value = "json")]
    pub output_format: String,

    #[arg(long)]
    pub output_file: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct VendorSpecificInfo {
    pub oui: String,
    pub vendor_type: Option<u8>,
    pub data_hex: String,
    pub length: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct DroneInfo {
    pub drone_id: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub altitude: Option<f32>,
    pub speed: Option<f32>,
}

#[derive(Debug, Serialize, Clone)]
pub struct BeaconInfo {
    pub packet_number: usize,
    pub source_mac: String,
    pub ssid: String,
    pub has_vendor_specific: bool,
    pub is_drone_id: bool,
    pub vendor_specific: Vec<VendorSpecificInfo>,
    pub drone_info: Option<DroneInfo>,
}

#[derive(Serialize)]
pub struct Report<'a> {
    pub args: &'a Args,
    pub messages: Vec<String>,
    pub beacons: Vec<BeaconInfo>,
}

#[derive(Serialize)]
pub struct BeaconCsvRow {
    pub packet_number: usize,
    pub source_mac: String,
    pub ssid: String,
    pub has_vendor_specific: bool,
    pub is_drone_id: bool,
}