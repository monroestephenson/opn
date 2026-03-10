use anyhow::Result;

use super::sort_sockets;
use crate::model::{QueryFilter, SocketEntry};
use crate::platform::Platform;
use crate::render;
use crate::render::table::Tabular;
use crate::render::RenderOutcome;
use crate::socket_display;

impl Tabular for SocketEntry {
    fn headers() -> Vec<&'static str> {
        vec![
            "PROTO",
            "LOCAL ADDRESS",
            "REMOTE ADDRESS",
            "STATE",
            "SERVICE",
            "PID",
            "PROCESS",
        ]
    }

    fn row(&self) -> Vec<String> {
        let local_port = self
            .local_addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(0);
        let service = crate::proto_detect::detect(local_port, &self.process.name)
            .unwrap_or("-")
            .to_string();
        vec![
            self.protocol.to_string(),
            socket_display::display_local_addr(self),
            socket_display::display_remote_addr(self),
            self.state.clone(),
            service,
            self.process.pid.to_string(),
            self.process.name.clone(),
        ]
    }
}

pub fn run(
    platform: &dyn Platform,
    port: u16,
    filter: &QueryFilter,
    json: bool,
) -> Result<RenderOutcome> {
    let mut entries = platform.find_by_port(port, filter)?;
    sort_sockets(&mut entries);
    Ok(render::render(&entries, json))
}
