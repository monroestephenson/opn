use anyhow::Result;

use crate::model::{QueryFilter, SocketEntry};
use crate::platform::Platform;
use crate::render;
use crate::render::RenderOutcome;
use crate::render::table::Tabular;

impl Tabular for SocketEntry {
    fn headers() -> Vec<&'static str> {
        vec!["PROTO", "LOCAL ADDRESS", "REMOTE ADDRESS", "STATE", "PID", "PROCESS"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.protocol.to_string(),
            self.local_addr.clone(),
            self.remote_addr.clone(),
            self.state.clone(),
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
    let entries = platform.find_by_port(port, filter)?;
    Ok(render::render(&entries, json))
}
