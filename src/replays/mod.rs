use chrono::{DateTime, Utc};

use crate::ArgsCommand;

pub mod udp_replay;

pub async fn create_replay_sender(args: &ArgsCommand) -> Option<impl ReplaySender> {
    match args {
        ArgsCommand::Dump {
            udp_replay: Some(_),
            ..
        } => udp_replay::UdpReplay::new(args).await,
        _ => None,
    }
}
pub trait ReplaySender
where
    Self: Sized,
{
    async fn new(cmd_args: &ArgsCommand) -> Option<Self>;
    async fn send(&mut self, ts: DateTime<Utc>, data: &[u8]);
    async fn end(&mut self);
}
