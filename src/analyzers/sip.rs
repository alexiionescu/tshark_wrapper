use super::ProtocolAnalyzer;
use crate::ArgsCommand;
use ahash::HashMap;
use chrono::{DateTime, Local, Utc};
use std::fmt::Write as _;

struct RegRequest {
    ts: DateTime<Utc>,
    expires: u16,
    auth_user: Option<String>,
}

#[derive(Default)]
struct RegisterStatus {
    from_addr: String,
    last_reported_ts: DateTime<Utc>,
    last_seen_ts: DateTime<Utc>,
    expires: u16,
    last_error_code: u16,
    repeat_count: u16,
    udp_streams: HashMap<u32, DateTime<Utc>>,
    last_stream: u32,
    errors: u32,
    last_error_ts: Option<DateTime<Utc>>,
    error_minutes: i64,
}

#[derive(Default)]
pub struct Analyzer {
    register_req: HashMap<(String, u16), RegRequest>,
    register_status: HashMap<String, RegisterStatus>,
    verbosity: u8,
}

const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S%.3f";

impl Analyzer {
    fn cleanup_old_register_req(&mut self, ts: DateTime<Utc>) {
        self.register_req.retain(|_k, v| {
            let diff = ts.signed_duration_since(v.ts);
            diff.num_seconds() < 180
        });
    }

    fn verified_expired_sessions(&mut self, ts: DateTime<Utc>) {
        for (user, status) in self
            .register_status
            .iter_mut()
            .filter(|(_, s)| s.expires > 0)
        {
            if (ts - status.last_seen_ts).num_seconds() > status.expires.into() {
                println!(
                    "{} REGISTER {user:<10} EXPIRED!!!  {} seconds ({})",
                    ts.with_timezone(&Local).format(TIME_FMT),
                    status.expires,
                    status.last_seen_ts.with_timezone(&Local).format(TIME_FMT)
                );
                status.expires = 0;
                status.repeat_count = 0;
                status.last_error_code = 0;
                status.udp_streams.clear();
                status.errors += 1;
                if status.last_error_ts.is_none() {
                    status.last_error_ts = Some(ts);
                }
            } else {
                status
                    .udp_streams
                    .retain(|_, last_seen| (ts - *last_seen).num_seconds() < status.expires.into());
            }
        }
    }
}

impl ProtocolAnalyzer for Analyzer {
    fn new(_cmd_args: &ArgsCommand, verbosity: u8) -> Self {
        Self {
            verbosity,
            ..Default::default()
        }
    }

    fn analyze(&mut self, ts: DateTime<Utc>, cols: Vec<&str>) {
        let from_addr = cols[0];
        let to_addr = cols[1];
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
        let udp_stream = cols[14].parse::<u32>().unwrap_or_default();
        let auth_user = cols[15];
        let mut output = String::with_capacity(200);
        self.verified_expired_sessions(ts);
        write!(
            output,
            "{} {method:<8} {from_user:<10} ",
            ts.with_timezone(&Local).format(TIME_FMT)
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
                            if status.last_error_code == 401 {
                                status.last_error_code = status_code;
                            }
                            status.last_seen_ts = ts;

                            let mut from_changed = false;
                            if expires != 0 && to_addr != status.from_addr {
                                from_changed = true;
                                status.from_addr = to_addr.into();
                            }
                            status.last_stream = udp_stream;
                            if status.udp_streams.insert(udp_stream, ts).is_none()
                                || status.expires != expires
                                || status.last_error_code != status_code
                                || from_changed
                                || status.last_error_ts.is_some()
                                || ts
                                    .signed_duration_since(status.last_reported_ts)
                                    .num_hours()
                                    >= 1
                            {
                                status.expires = expires;
                                status.last_error_code = status_code;
                                status.last_reported_ts = ts;
                                status.repeat_count = 0;
                                if expires != 0 {
                                    if let Some(err_ts) = status.last_error_ts.take() {
                                        let err_time = (ts - err_ts).num_minutes();
                                        println!(
                                            "{output}{status_code:03}/OK      Expires:{expires:4} ({:2},{udp_stream:4}) {:<15} Last Error: {} minutes.",
                                            status.repeat_count, status.from_addr, err_time
                                        );
                                        status.error_minutes += err_time;
                                    } else {
                                        println!(
                                            "{output}{status_code:03}/OK      Expires:{expires:4} ({:2},{udp_stream:4}) {:<15}",
                                            status.repeat_count, status.from_addr
                                        );
                                    }
                                }
                            } else {
                                status.repeat_count += 1;
                            }
                        } else {
                            if expires != 0 {
                                println!("{output}{status_code:03}/OK      Expires:{expires:4} ( F,{udp_stream:4}) {:<15}",to_addr);
                            }
                            self.register_status.insert(
                                key.0.clone(),
                                RegisterStatus {
                                    from_addr: to_addr.into(),
                                    last_reported_ts: ts,
                                    last_seen_ts: ts,
                                    expires,
                                    last_error_code: status_code,
                                    udp_streams: HashMap::from_iter(std::iter::once((
                                        udp_stream, ts,
                                    ))),
                                    ..Default::default()
                                },
                            );
                        }
                    }
                    300..400 => {
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            status.last_seen_ts = ts;
                            if status.last_error_code != status_code
                                || ts
                                    .signed_duration_since(status.last_reported_ts)
                                    .num_hours()
                                    >= 1
                            {
                                status.last_error_code = status_code;
                                status.last_reported_ts = ts;
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
                                    from_addr: to_addr.into(),
                                    last_reported_ts: ts,
                                    last_seen_ts: ts,
                                    expires: 0,
                                    last_error_code: status_code,
                                    udp_streams: HashMap::from_iter(std::iter::once((
                                        udp_stream, ts,
                                    ))),
                                    ..Default::default()
                                },
                            );
                        }
                    }
                    400 | 402..407 | 408..500 => {
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            status.last_seen_ts = ts;
                            if status.last_error_code != status_code
                                || ts
                                    .signed_duration_since(status.last_reported_ts)
                                    .num_hours()
                                    >= 1
                            {
                                status.last_error_code = status_code;
                                status.last_reported_ts = ts;
                                status.repeat_count = 0;
                                status.errors += 1;
                                if status.last_error_ts.is_none() {
                                    status.last_error_ts = Some(ts);
                                }
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
                                    from_addr: to_addr.into(),
                                    last_reported_ts: ts,
                                    last_seen_ts: ts,
                                    expires: 0,
                                    errors: 1,
                                    last_error_code: status_code,
                                    ..Default::default()
                                },
                            );
                        }
                    }
                    0 => {
                        self.cleanup_old_register_req(ts);

                        if let Some(req) = self.register_req.get_mut(&key) {
                            let diff = ts.signed_duration_since(req.ts);
                            req.auth_user = (!auth_user.is_empty()).then_some(auth_user.into());
                            if diff.num_seconds() > 20 {
                                if let Some(status) = self.register_status.get_mut(&key.0) {
                                    status.last_seen_ts = ts;
                                    if status.expires != 0 || status.last_error_code != 408 || {
                                        ts.signed_duration_since(status.last_reported_ts)
                                            .num_hours()
                                            >= 1
                                    } {
                                        status.last_error_code = 408;
                                        status.last_reported_ts = ts;
                                        status.expires = 0;
                                        status.errors += 1;
                                        if status.last_error_ts.is_none() {
                                            status.last_error_ts = Some(ts);
                                        }
                                        status.udp_streams.remove(&udp_stream);
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
                                    println!(
                                        "{output}408/Timeout {} s {:<15}",
                                        diff.num_seconds(),
                                        from_addr
                                    );
                                    self.register_status.insert(
                                        key.0.clone(),
                                        RegisterStatus {
                                            from_addr: from_addr.into(),
                                            last_reported_ts: ts,
                                            last_seen_ts: ts,
                                            expires: 0,
                                            errors: 1,
                                            last_error_code: 408,
                                            ..Default::default()
                                        },
                                    );
                                }
                            }
                        } else {
                            self.register_req.insert(
                                key,
                                RegRequest {
                                    ts,
                                    expires,
                                    auth_user: (!auth_user.is_empty()).then_some(auth_user.into()),
                                },
                            );
                        }
                        return;
                    }
                    407 => {
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            status.last_seen_ts = ts;
                        }
                    }
                    401 => {
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            status.last_seen_ts = ts;
                            if let Some(RegRequest {
                                auth_user: Some(user_name),
                                ..
                            }) = self.register_req.get(&key)
                            {
                                if status.last_error_code == 401 && status.last_stream == udp_stream
                                {
                                    status.errors += 1;
                                    if status.last_error_ts.is_none() {
                                        status.last_error_ts = Some(ts);
                                    }
                                    println!("{output}401/Unauthorized {user_name}");
                                }
                            }
                            status.last_stream = udp_stream;
                            status.last_error_code = 401;
                        }
                    }
                    _ => {
                        if let Some(status) = self.register_status.get_mut(&key.0) {
                            status.last_seen_ts = ts;
                        }
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
            m if !m.is_empty() => {
                if status_code > 0 {
                    println!("{output}<<-{to_user:>8} {status_code:03} CID:{call_id}");
                } else {
                    println!("{output}->>{to_user:>8} REQ CID:{call_id}");
                }
            }
            _ => (),
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
        tshark_args.push("-e");
        tshark_args.push("udp.stream");
        tshark_args.push("-e");
        tshark_args.push("sip.auth.username");
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
        let mut output = String::with_capacity(200);
        println!("\n ------------ Register Status ------------ \n");
        if self.verbosity > 1 {
            eprintln!("\n ------------ Register Status ------------ \n");
        }
        let mut keys = Vec::from_iter(self.register_status.keys());
        keys.sort();
        let mut registered = 0;
        let mut total_errors = 0;
        let mut total_errors_time = 0;
        for user in keys {
            let status = self.register_status.get(user).unwrap();
            total_errors += status.errors;
            total_errors_time += status.error_minutes;

            let registered = if status.expires > 0 {
                registered += 1;
                "REGISTERED"
            } else {
                "UNREGISTERED"
            };
            write!(
                output,
                "{user:12} {registered:12} from {:<15}\t{:3} errors for {:4} minutes",
                status.from_addr, status.errors, status.error_minutes
            )
            .unwrap();
            if status.udp_streams.len() > 1 {
                write!(output, "\t{} streams: ", status.udp_streams.len(),).unwrap();
                for ts in status.udp_streams.values() {
                    write!(output, "{}, ", ts.with_timezone(&Local).format(TIME_FMT)).unwrap();
                }
            } else {
                write!(
                    output,
                    "\tlast seen: {}",
                    status.last_seen_ts.with_timezone(&Local).format(TIME_FMT)
                )
                .unwrap();
            }
            println!("{}", output);
            if self.verbosity > 1 {
                eprintln!("{}", output);
            }
            output.clear();
        }
        writeln!(
            output,
            r#"
--------- STATS -----------
- total users registered: {registered}
- total users un-registered: {}
- total errors: {total_errors}
- total errors time: {total_errors_time} minutes
- registered requests pending: {}
"#,
            self.register_status.len() - registered,
            self.register_req.len(),
        )
        .unwrap();
        println!("{}", output);
        if self.verbosity > 0 {
            eprintln!("{}", output);
        }
    }
}
