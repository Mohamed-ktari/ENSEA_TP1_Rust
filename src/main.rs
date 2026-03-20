use clap::Parser;
use TP1::{parse_pcap_file, save_output}; // assuming your crate name is tp1_lib

#[derive(clap::Parser, Debug)]
#[command(author, version, about = "Network packet analyzer")]
struct Args {
    #[arg(long)]
    pcap: Option<String>,

    #[arg(long, default_value = "json")]
    output_format: String,

    #[arg(long)]
    output_file: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let filename = args.pcap.as_ref().expect("No PCAP file provided");

    let output = parse_pcap_file(filename)?;
    save_output(&output, &args.output_format, args.output_file.as_deref())?;

    Ok(())
}