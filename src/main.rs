use babeltrace2_sys::internal_api::{PacketDecoder, PacketDecoderConfig};
use bytes::{buf::BufMut, BytesMut};
use clap::{Parser, Subcommand};
use std::{
    collections::{hash_map::Entry, HashMap},
    fs,
    io::{BufReader, Read, Write},
    path::PathBuf,
};
use tracing::{debug, trace, warn};

#[derive(Parser, Debug, Clone)]
#[clap(version, about = "Utilities for working with CTF streams", long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    SplitStream(SplitStreamCmd),
}

/// Splits a multi-stream file into files-per-stream to be compatible with babeltrace
#[derive(Parser, Debug, Clone)]
pub struct SplitStreamCmd {
    /// Path to CTF metadata file
    pub metadata: PathBuf,

    /// Path to combined binary CTF streams to split
    pub stream: PathBuf,

    /// Output directory to write the split streams to
    #[clap(long, short = 'o', default_value = "streams")]
    pub output: PathBuf,
}

fn main() {
    match do_main() {
        Ok(()) => (),
        Err(e) => {
            eprintln!("{e}");
            let mut cause = e.source();
            while let Some(err) = cause {
                eprintln!("Caused by: {err}");
                cause = err.source();
            }
            std::process::exit(exitcode::SOFTWARE);
        }
    }
}

fn do_main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();

    tracing_subscriber::fmt::init();

    let Commands::SplitStream(cmd) = &opts.cmd;
    do_split_stream(cmd)?;

    Ok(())
}

fn do_split_stream(cmd: &SplitStreamCmd) -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = &cmd.output;

    fs::create_dir_all(out_dir)?;

    let reader = BufReader::new(fs::File::open(&cmd.stream)?);

    debug!(metadata = %cmd.metadata.display(), "Creating decoder");
    let cfg = PacketDecoderConfig::default();
    let mut dec = PacketDecoder::new(&cmd.metadata, &cfg)?;
    let mut src = BytesMut::new();
    let mut stream_id_to_file = HashMap::new();

    for byte in reader.bytes() {
        let byte = byte?;

        src.put_u8(byte);

        match dec.packet_properties(&src) {
            Err(_e) => {
                // Assume this is because not enough bytes to parse full packet header
                continue;
            }
            Ok(None) => continue,
            Ok(Some(props)) => {
                trace!(?props);

                let Some(stream_id) = props.stream_class_id else {
                    warn!("Packet stream class ID is missing");
                    src.clear();
                    continue;
                };

                let Some(packet_total_size_bits) = props.packet_total_size_bits else {
                    warn!("Packet total size bits is missing");
                    src.clear();
                    continue;
                };

                let size_bytes = (packet_total_size_bits >> 3) as usize;

                // These can be zero while we're filling the buffer
                // TODO make a better heuristic
                if packet_total_size_bits == 0 || size_bytes == 0 {
                    continue;
                }

                // We've got enough bytes for the packet header,
                // but not the whole packet yet, wait for more bytes
                // before doing other checks
                if size_bytes > src.len() {
                    continue;
                }

                let pkt = src.split_to(size_bytes);
                debug!(
                    stream_id,
                    size_bytes,
                    remaining = src.len(),
                    "Processing packet"
                );

                let out_file = match stream_id_to_file.entry(stream_id) {
                    Entry::Occupied(o) => o.into_mut(),
                    Entry::Vacant(v) => {
                        let filename = format!("stream{stream_id}");
                        let out_path = out_dir.join(&filename);
                        debug!(file = %out_path.display(), "Create stream file");
                        let f = fs::File::create(out_path)?;
                        v.insert(f)
                    }
                };

                out_file.write_all(&pkt)?;
            }
        }
    }

    Ok(())
}
