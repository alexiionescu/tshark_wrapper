use super::ProtocolAnalyzer;
use crate::ArgsCommand;
use chrono::{DateTime, Utc};
use std::fmt::Write as _;

pub struct Analyzer {}

const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S%.3f";

impl ProtocolAnalyzer for Analyzer {
    fn new(_cmd_args: &ArgsCommand) -> Self {
        Analyzer {}
    }

    fn analyze(&self, ts: DateTime<Utc>, cols: Vec<&str>) {
        let _from_addr = cols[0];
        let _to_addr = cols[1];
        let from_user = cols[2];
        let _from_host = cols[3];
        let to_user = cols[4];
        let _to_host = cols[5];
        let method = cols[6];
        let _seq = cols[7];
        let status_code = cols[8].parse::<u16>().unwrap_or_default();
        let expires = cols[9];
        let sdp_addr = cols[10];
        let sdp_port = cols[11];
        let call_id = cols[12];
        let from_display = cols[13];
        let mut output = String::with_capacity(200);
        write!(
            output,
            "{} {method:<8} {from_user:<7} ",
            ts.format(TIME_FMT)
        )
        .unwrap();
        match method {
            "REGISTER" => match status_code {
                200..299 => {
                    write!(output, "{status_code:03}/OK      Expires:{expires}").unwrap();
                }
                402..406 | 408..499 => {
                    write!(output, "{status_code:03}/Error").unwrap();
                }
                _ => return,
            },
            "INVITE" | "BYE" | "CANCEL" | "ACK" => {
                if status_code > 0 {
                    write!(output, "<<-{to_user:>8} {status_code:03} CID:{call_id}").unwrap();
                } else {
                    write!(output, "->>{to_user:>8} REQ CID:{call_id}").unwrap();
                }
                if !from_display.is_empty() {
                    write!(output, " From: {from_display}").unwrap();
                }
                if !sdp_addr.is_empty() {
                    write!(output, " MEDIA {sdp_addr}:{sdp_port} ").unwrap();
                }
            }
            _ => {
                if status_code > 0 {
                    write!(output, "<<-{to_user:>8} {status_code:03} CID:{call_id}").unwrap();
                } else {
                    write!(output, "->>{to_user:>8} REQ CID:{call_id}").unwrap();
                }
            }
        }
        println!("{}", output);
    }

    fn add_protocol_fields(&self, tshark_args: &mut Vec<&str>) {
        tshark_args.push("-e");
        tshark_args.push("sip.from.user");
        tshark_args.push("-e");
        tshark_args.push("sip.from.host");
        tshark_args.push("-e");
        tshark_args.push("sip.to.user");
        tshark_args.push("-e");
        tshark_args.push("sip.to.host");
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
        tshark_args.push("-e");
        tshark_args.push("sip.Call-ID");
        tshark_args.push("-e");
        tshark_args.push("sip.from.display.info");
        if !tshark_args.contains(&"-Y") {
            tshark_args.push("-Y");
            tshark_args.push("sip");
        }
        if tshark_args.contains(&"-i") && !tshark_args.contains(&"-f") {
            tshark_args.push("-f");
            tshark_args.push("udp port 5060");
        }
    }
}
