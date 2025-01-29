use chrono::{DateTime, Utc};

use crate::{Args, ArgsCommand};

mod sip;

pub fn create_analyzer(args: &Args) -> Option<impl ProtocolAnalyzer> {
    match &args.cmd {
        ArgsCommand::Analyzer => {
            if let Some(protocol) = args.protocol.as_deref() {
                match protocol {
                    "sip" => Some(sip::Analyzer::new(&args.cmd)),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

pub trait ProtocolAnalyzer
where
    Self: Sized,
{
    fn add_protocol_fields(&self, tshark_args: &mut Vec<&str>);
    fn new(cmd_args: &ArgsCommand) -> Self;
    fn analyze(&mut self, ts: DateTime<Utc>, cols: Vec<&str>);
    fn end(&mut self);
}
