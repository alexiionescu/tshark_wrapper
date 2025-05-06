use std::net::Ipv4Addr;

use tokio::net::UdpSocket;

use chrono::{DateTime, Utc};

use crate::ArgsCommand;

use super::ReplaySender;
pub struct UdpReplay {
    socket: UdpSocket,
    replay_contraction: u64,
    replay_min_ms: u64,
    replay_max_ms: u64,
    last_ts: Option<DateTime<Utc>>,
}

impl ReplaySender for UdpReplay {
    async fn new(cmd_args: &ArgsCommand) -> Option<Self> {
        if let ArgsCommand::Dump {
            udp_replay: Some(addr),
            replay_contraction,
            replay_min_ms,
            replay_max_ms,
            ..
        } = cmd_args
        {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
            socket.connect(addr).await.ok()?;
            return Some(UdpReplay {
                socket,
                replay_contraction: *replay_contraction,
                replay_min_ms: *replay_min_ms,
                replay_max_ms: *replay_max_ms,
                last_ts: None,
            });
        }
        None
    }

    async fn send(&mut self, ts: DateTime<Utc>, data: &[u8]) {
        let sleep_time = if let Some(last_ts) = self.last_ts {
            let diff = ts.signed_duration_since(last_ts).num_milliseconds();
            if diff > 0 {
                (diff as u64 / self.replay_contraction)
                    .clamp(self.replay_min_ms, self.replay_max_ms)
            } else {
                0
            }
        } else {
            0
        };
        self.last_ts = Some(ts);
        if sleep_time > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(sleep_time)).await;
        }
        self.socket.send(data).await.ok();
    }
    async fn end(&mut self) {}
}
