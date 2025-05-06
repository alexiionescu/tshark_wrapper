use chrono::{NaiveDateTime, TimeZone as _, Utc};
use clap::{ArgAction, Parser, Subcommand, command};
use glob::glob;
use regex::Regex;
use replays::ReplaySender;
use std::{path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    process::Command,
    signal,
    sync::broadcast,
    task,
};
use utils::str::MaybeReplaceVecExt as _;
mod replays;
mod utils;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: ArgsCommand,
    #[clap(short)]
    interface: Option<String>,
    #[clap(short = 'f')]
    capture_filter: Option<String>,
    #[clap(short = 'Y')]
    display_filter: Option<String>,
    #[clap(short = 'r', help = "Read packets from a pcap file")]
    read_file: Option<String>,
    #[clap(short = 'd', help = "Decoda packets as (e.g udp.port==5060,sip)")]
    decode_as: Option<String>,
    #[clap(short = 'p', help = "protocol")]
    protocol: Option<String>,
    #[clap(short = 'v', action = ArgAction::Count, help = "verbosity level (e.g. -vvv)")]
    verbosity: u8,
}

mod analyzers;
use analyzers::*;
#[derive(Subcommand)]
enum ArgsCommand {
    Dump {
        #[clap(short = 'e', long, help = "Regex for filtering output lines")]
        output_regex: Option<Regex>,
        #[clap(short = 't', long, help = "Decoda Data As Text")]
        text: bool,
        #[clap(long, help = "Replay text to udp address:port")]
        udp_replay: Option<String>,
        #[clap(long, help = "Replay min time in milliseconds", default_value = "0")]
        replay_min_ms: u64,
        #[clap(
            long,
            help = "Replay max time in milliseconds",
            default_value = "99999999999999"
        )]
        replay_max_ms: u64,
        #[clap(
            long,
            help = "Replay time contraction from capture timestamps",
            default_value = "1"
        )]
        replay_contraction: u64,
    },
    Analyzer,
}

const FIX_FIELDS: usize = 3;
#[tokio::main]
async fn main() {
    let args = Args::parse();
    let (shutdown_tx, _) = broadcast::channel(1);
    let shutdown_tx_clone = shutdown_tx.clone();
    task::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        eprintln!("\nCtrl+C received, sending shutdown signal.");
        shutdown_tx_clone.send(()).ok();
    });

    let mut tshark_args = vec![
        "-Q",
        "-l",
        "-T",
        "fields",
        "-e",
        "_ws.col.Time",
        "-e",
        "_ws.col.Source",
        "-e",
        "_ws.col.Destination",
    ];
    if let Some(f) = args.display_filter.as_ref() {
        tshark_args.push("-Y");
        tshark_args.push(f.as_str());
    }
    let mut read_idx = 0;
    let paths = if let Some(f) = args.read_file.as_ref() {
        tshark_args.push("-r");
        tshark_args.push("");
        read_idx = tshark_args.len() - 1;
        Vec::from_iter(glob(f).expect("Invalid File glob pattern").flatten())
    } else {
        vec![PathBuf::default()]
    };
    if let Some(f) = args.interface.as_ref() {
        tshark_args.push("-i");
        tshark_args.push(f.as_str());
    }
    if let Some(f) = args.capture_filter.as_ref() {
        tshark_args.push("-f");
        tshark_args.push(f.as_str());
    }
    if let Some(d) = args.decode_as.as_ref() {
        tshark_args.push("-d");
        tshark_args.push(d.as_str());
    }
    let mut analyzer = create_analyzer(&args);
    let mut replayer = replays::create_replay_sender(&args.cmd).await;
    let mut data_field = 0;
    match &args.cmd {
        ArgsCommand::Dump { .. } => {
            if replayer.is_some() {
                tshark_args.push("-t");
                tshark_args.push("e.6");
            } else {
                tshark_args.push("-t");
                tshark_args.push("ad");
            }
            data_field = add_dump_protocol_fields(&mut tshark_args, &args);
        }
        ArgsCommand::Analyzer => {
            if let Some(analyzer) = &analyzer {
                tshark_args.push("-t");
                tshark_args.push("e.6");
                analyzer.add_protocol_fields(&mut tshark_args);
            } else {
                eprintln!("No analyzer for protocol {:?}", args.protocol);
                return;
            }
        }
    }

    for path in paths {
        let mut tshark_args = tshark_args.clone();
        if read_idx > 0 {
            tshark_args[read_idx] = path
                .as_os_str()
                .to_str()
                .expect("Invalid non-unicode path string");
        }
        if args.verbosity > 2 {
            eprintln!("tshark '{}'", tshark_args.join("' '"));
        }

        let mut cmd = Command::new("tshark")
            .args(tshark_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("cannot spawn");

        let stdout = cmd.stdout.take().expect("no process stdout");

        let mut lines = BufReader::new(stdout).lines();

        let mut shutdown_rx1 = shutdown_tx.subscribe();
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            process_line(line, &args.cmd, &mut analyzer,  &mut replayer, data_field).await;
                        }
                        Err(e) => {
                            eprintln!("error reading line: {}", e);
                            break;
                        }
                        _ => {
                            break;
                        }
                    }

                }
                _ = shutdown_rx1.recv() => {
                    println!("Main Loop shutting down...");
                    break;
                }
            }
        }

        while let Ok(Some(line)) = lines.next_line().await {
            process_line(
                line,
                &args.cmd,
                &mut analyzer,
                &mut None::<replays::udp_replay::UdpReplay>,
                data_field,
            )
            .await;
        }
        cmd.kill()
            .await
            .map_err(|e| eprintln!("error killing process: {}", e))
            .ok();
        cmd.wait()
            .await
            .map_err(|e| eprintln!("error waiting for process: {}", e))
            .ok();
    }

    if let Some(replayer) = &mut replayer {
        replayer.end().await;
    }
    if let Some(analyzer) = &mut analyzer {
        analyzer.end();
    }
}

fn add_dump_protocol_fields(tshark_args: &mut Vec<&str>, args: &Args) -> usize {
    if let Some(protocol) = args.protocol.as_deref() {
        match protocol {
            "tcp" => {
                tshark_args.push("-e");
                tshark_args.push("tcp.srcport");
                tshark_args.push("-e");
                tshark_args.push("tcp.dstport");
                tshark_args.push("-e");
                tshark_args.push("_ws.col.Info");
                tshark_args.push("-e");
                tshark_args.push("data");
                FIX_FIELDS + 3
            }
            "udp" => {
                tshark_args.push("-e");
                tshark_args.push("udp.srcport");
                tshark_args.push("-e");
                tshark_args.push("udp.dstport");
                tshark_args.push("-e");
                tshark_args.push("data");
                FIX_FIELDS + 2
            }
            "sip" => {
                tshark_args.push("-e");
                tshark_args.push("sip.from.addr");
                tshark_args.push("-e");
                tshark_args.push("sip.to.addr");
                tshark_args.push("-e");
                tshark_args.push("sip.CSeq.method");
                tshark_args.push("-e");
                tshark_args.push("sip.CSeq.seq");
                tshark_args.push("-e");
                tshark_args.push("sip.Status-Code");
                tshark_args.push("-e");
                tshark_args.push("sip.Expires");
                tshark_args.push("-e");
                tshark_args.push("sdp.connection_info.address");
                tshark_args.push("-e");
                tshark_args.push("sdp.media.port");
                if !tshark_args.contains(&"-Y") {
                    tshark_args.push("-Y");
                    tshark_args.push("sip");
                }
                if tshark_args.contains(&"-i") && !tshark_args.contains(&"-f") {
                    tshark_args.push("-f");
                    tshark_args.push("udp port 5060");
                }
                0
            }
            _ => {
                tshark_args.push("-e");
                tshark_args.push("_ws.col.Info");
                0
            }
        }
    } else {
        0
    }
}

async fn process_line(
    line: String,
    cmd_args: &ArgsCommand,
    analyzer: &mut Option<impl ProtocolAnalyzer>,
    replayer: &mut Option<impl ReplaySender>,
    data_field: usize,
) {
    match cmd_args {
        ArgsCommand::Dump {
            output_regex, text, ..
        } => {
            let line = if data_field > 0 {
                let mut split_out = line.split('\t').collect::<Vec<&str>>();
                if split_out.len() <= data_field {
                    line
                } else if let Ok(raw_hex) = hex::decode(split_out[data_field]) {
                    if let Some(replayer) = replayer {
                        let dt = NaiveDateTime::parse_from_str(split_out[0], "%s.%6f")
                            .map(|d| Utc.from_utc_datetime(&d))
                            .unwrap_or_default();
                        replayer.send(dt, &raw_hex).await;
                    }
                    if *text {
                        let raw_hex = raw_hex
                            .maybe_replace_buf(b"\r", b"<CR>")
                            .maybe_replace_buf(b"\n", b"<LF>")
                            .maybe_replace_buf(b"\t", b"<TAB>")
                            .maybe_replace_buf(b"\x00", b"<NUL>")
                            .maybe_replace_buf(b"\x02", b"<STX>")
                            .maybe_replace_buf(b"\x03", b"<ETX>")
                            .maybe_replace_buf(b"\x04", b"<EOT>");
                        if let Ok(s) = String::from_utf8(raw_hex) {
                            split_out[data_field] = &s;
                            split_out.join("\t")
                        } else {
                            line
                        }
                    } else {
                        line
                    }
                } else {
                    line
                }
            } else {
                line
            };
            if let Some(re) = output_regex {
                if re.is_match(&line) {
                    println!("{}", line);
                }
            } else {
                println!("{}", line);
            }
        }
        ArgsCommand::Analyzer => analyze_line(&line, cmd_args, analyzer),
    }
}

fn analyze_line(line: &str, _cmd_args: &ArgsCommand, analyzer: &mut Option<impl ProtocolAnalyzer>) {
    let split_out = line.split('\t').collect::<Vec<&str>>();
    let dt = NaiveDateTime::parse_from_str(split_out[0], "%s.%6f")
        .map(|d| Utc.from_utc_datetime(&d))
        .unwrap_or_default();
    if let Some(analyzer) = analyzer {
        analyzer.analyze(dt, split_out[1..].to_vec());
    }
}

#[cfg(test)]
mod test {
    use chrono::{DateTime, TimeZone as _, Utc};

    #[test]
    fn parse_time() {
        let time = "1738062028.284088";
        let dt = chrono::NaiveDateTime::parse_from_str(time, "%s.%6f")
            .map(|d| Utc.from_utc_datetime(&d));
        assert_eq!(
            dt,
            Ok(DateTime::<Utc>::from_timestamp(1738062028, 284088000).unwrap())
        );
    }
}
