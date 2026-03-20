use crate::pcap_parser::Output;
use std::fs::File;
use std::io::{self, Write};

pub fn save_output(
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

            // Beacons
            for beacon in &output.beacons {
                wtr.write_record(&[
                    &beacon.ssid,
                    &beacon.mac,
                    &beacon.channel.unwrap_or(0).to_string(),
                    &beacon.signal_dbm.unwrap_or(0).to_string(),
                    &beacon.rates.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(","),
                    "", "", "", "", // drone fields
                ])?;
            }

            // Drones
            for drone in &output.drones {
                wtr.write_record(&[
                    "", "", "", "", "", // beacon fields
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