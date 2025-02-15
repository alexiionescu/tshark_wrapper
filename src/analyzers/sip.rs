use super::ProtocolAnalyzer;
use crate::ArgsCommand;
use ahash::HashMap;
use chrono::{DateTime, Utc};
use std::fmt::Write as _;

struct RegRequest {
    ts: DateTime<Utc>,
    expires: u16,
}

#[derive(Default)]
struct RegisterStatus {
    last_ts: DateTime<Utc>,
    expires: u16,
    last_error_code: u16,
    repeat_count: u16,
}

#[derive(Default)]
pub struct Analyzer {
    register_req: HashMap<(String, u16), RegRequest>,
    register_status: HashMap<String, RegisterStatus>,
}

const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S%.3f";

impl Analyzer {
    fn cleanup_old_register_req(&mut self, ts: DateTime<Utc>) {
        self.register_req.retain(|_k, v| {
            let diff = ts.signed_duration_since(v.ts);
            diff.num_seconds() < 180
        });
    }
}

impl ProtocolAnalyzer for Analyzer {
    fn new(_cmd_args: &ArgsCommand) -> Self {
        Analyzer::default()
    }

    fn analyze(&mut self, ts: DateTime<Utc>, cols: Vec<&str>) {
        let _from_addr = cols[0];
        let _to_addr = cols[1];
        let from_user = cols[2];
        let _from_host = cols[3];
        let to_user = cols[4];
        let _to_host = cols[5];
        let method = cols[6];
        let seq = cols[7].parse::<u16>().unwrap_or_default();
        let status_code = cols[8].parse::<u16>().unwrap_or_default();
        let sdp_addr = cols[10];
        let sdp_port = cols[11];
        let call_id = cols[12];
        let from_display = cols[13];
        let mut output = String::with_capacity(200);
        write!(
            output,
            "{} {method:<8} {from_user:<10} ",
            ts.format(TIME_FMT)
        )
        .unwrap();
        match method {
            "REGISTER" => {
                let key = (from_user.to_string(), seq);
                let mut expires = cols[9].parse::<u16>().unwrap_or_default();
                match status_code {
                    200..300 => {
                        if expires == 0 {
                            if let Some(req) = self.register_req.get(&key) {
                                expires = req.expires;
                            }
                        }
                        if expires == 0 {
                            println!("{output}{status_code:03}/OK      UNREGISTERED");
                        }
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            if status.expires != expires
                                || status.last_error_code != status_code
                                || ts.signed_duration_since(status.last_ts).num_hours() >= 1
                            {
                                status.expires = expires;
                                status.last_error_code = status_code;
                                status.last_ts = ts;
                                status.repeat_count = 0;
                                if expires != 0 {
                                    println!(
                                        "{output}{status_code:03}/OK      Expires:{expires} ({})",
                                        status.repeat_count
                                    );
                                }
                            } else {
                                status.repeat_count += 1;
                            }
                        } else {
                            if expires != 0 {
                                println!("{output}{status_code:03}/OK      Expires:{expires}");
                            }
                            self.register_status.insert(
                                key.0.clone(),
                                RegisterStatus {
                                    last_ts: ts,
                                    expires,
                                    last_error_code: status_code,
                                    ..Default::default()
                                },
                            );
                        }
                    }
                    300..400 => {
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            if status.last_error_code != status_code
                                || ts.signed_duration_since(status.last_ts).num_hours() >= 1
                            {
                                status.last_error_code = status_code;
                                status.last_ts = ts;
                                status.repeat_count = 0;
                                println!(
                                    "{output}{status_code:03}/Redirect ({})",
                                    status.repeat_count
                                );
                            } else {
                                status.repeat_count += 1;
                            }
                        } else {
                            println!("{output}{status_code:03}/Redirect");
                            self.register_status.insert(
                                key.0.clone(),
                                RegisterStatus {
                                    last_ts: ts,
                                    expires: 0,
                                    last_error_code: status_code,
                                    ..Default::default()
                                },
                            );
                        }
                    }
                    400 | 402..407 | 408..500 => {
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            if status.last_error_code != status_code
                                || ts.signed_duration_since(status.last_ts).num_hours() >= 1
                            {
                                status.last_error_code = status_code;
                                status.last_ts = ts;
                                status.repeat_count = 0;
                                println!(
                                    "{output}{status_code:03}/Error ({})",
                                    status.repeat_count
                                );
                            } else {
                                status.repeat_count += 1;
                            }
                        } else {
                            println!("{output}{status_code:03}/Error");
                            self.register_status.insert(
                                key.0.clone(),
                                RegisterStatus {
                                    last_ts: ts,
                                    expires: 0,
                                    last_error_code: status_code,
                                    ..Default::default()
                                },
                            );
                        }
                    }
                    0 => {
                        self.cleanup_old_register_req(ts);

                        if let Some(req) = self.register_req.get(&key) {
                            let diff = ts.signed_duration_since(req.ts);
                            if diff.num_seconds() > 20 {
                                if let Some(status) = self.register_status.get_mut(&key.0) {
                                    if status.expires != 0 || status.last_error_code != 408 || {
                                        ts.signed_duration_since(status.last_ts).num_hours() >= 1
                                    } {
                                        status.last_error_code = 408;
                                        status.last_ts = ts;
                                        status.expires = 0;
                                        status.repeat_count = 0;
                                        println!(
                                            "{output}408/Timeout {} s ({})",
                                            diff.num_seconds(),
                                            status.repeat_count
                                        );
                                    } else {
                                        status.repeat_count += 1;
                                    }
                                } else {
                                    println!("{output}408/Timeout {} s", diff.num_seconds());
                                    self.register_status.insert(
                                        key.0.clone(),
                                        RegisterStatus {
                                            last_ts: ts,
                                            expires: 0,
                                            last_error_code: 408,
                                            ..Default::default()
                                        },
                                    );
                                }
                            }
                        } else {
                            self.register_req.insert(key, RegRequest { ts, expires });
                        }
                        return;
                    }
                    401 | 407 => {}
                    _ => {
                        println!("{output}{status_code:03}/Unknown");
                    }
                }
                self.register_req.remove(&key);
            }
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
                println!("{output}");
            }
            _ => {
                if status_code > 0 {
                    println!("{output}<<-{to_user:>8} {status_code:03} CID:{call_id}");
                } else {
                    println!("{output}->>{to_user:>8} REQ CID:{call_id}");
                }
            }
        }
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

    fn end(&mut self) {
        println!(
            "End of SIP analyzer\n - registered requests pending: {}",
            self.register_req.len()
        );
    }
}
