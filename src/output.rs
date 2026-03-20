use crate::models::{BeaconCsvRow, Report};
use std::fs::File;
use std::io;

pub fn save_report(
    report: &Report,
    output_format: &str,
    output_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match output_format.to_lowercase().as_str() {
        "json" => save_as_json(report, output_file)?,
        "csv" => save_as_csv(report, output_file)?,
        other => return Err(format!("Unsupported output format: {}", other).into()),
    }

    Ok(())
}

fn save_as_json(
    report: &Report,
    output_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(file_name) = output_file {
        let file = File::create(file_name)?;
        serde_json::to_writer_pretty(file, report)?;
    } else {
        let stdout = io::stdout();
        let handle = stdout.lock();
        serde_json::to_writer_pretty(handle, report)?;
    }

    Ok(())
}

fn save_as_csv(
    report: &Report,
    output_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_name = output_file.unwrap_or("results.csv");
    let mut writer = csv::Writer::from_path(file_name)?;

    for beacon in &report.beacons {
        let row = BeaconCsvRow {
            packet_number: beacon.packet_number,
            source_mac: beacon.source_mac.clone(),
            ssid: beacon.ssid.clone(),
            has_vendor_specific: beacon.has_vendor_specific,
            is_drone_id: beacon.is_drone_id,
        };

        writer.serialize(row)?;
    }

    writer.flush()?;
    Ok(())
}