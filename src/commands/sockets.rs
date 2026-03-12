use anyhow::Result;
use std::time::Duration;

use super::sort_sockets;
use crate::model::QueryFilter;
use crate::platform::Platform;
use crate::render;
use crate::render::RenderOutcome;

pub fn run(platform: &dyn Platform, filter: &QueryFilter, json: bool) -> Result<RenderOutcome> {
    let mut entries = platform.list_sockets(filter)?;
    let backend = platform.socket_backend_label();
    let backend_detail = platform.socket_backend_detail();
    let strict_live = platform.strict_live_socket_mode();

    if entries.is_empty() && platform.supports_live_socket_activity() {
        let observed = platform.wait_for_socket_activity(Duration::from_millis(750))?;
        if observed {
            entries = platform.list_sockets(filter)?;
        }
    }

    sort_sockets(&mut entries);
    let outcome = render::render(&entries, json);
    if !json {
        match outcome {
            crate::render::RenderOutcome::HasResults => {
                match backend_detail {
                    Some(detail) => eprintln!("\nbackend: {backend} ({detail})"),
                    None => eprintln!("\nbackend: {backend}"),
                }
                eprintln!(
                    "Tip: run 'opn diagnose' for a full network snapshot with anomaly detection."
                );
            }
            crate::render::RenderOutcome::NoResults if strict_live => {
                eprintln!(
                    "backend: {backend} (strict live mode)\n\
                     no live socket flows were observed during the startup window; \
                     run `opn watch` or `opn history record` and generate traffic to populate the live table."
                );
            }
            crate::render::RenderOutcome::NoResults => {
                eprintln!("backend: {backend}");
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProcessInfo, Protocol, SocketEntry};
    use crate::platform::mock::MockPlatform;
    use std::sync::Arc;

    fn make_socket(pid: u32, name: &str, local: &str, proto: Protocol) -> SocketEntry {
        SocketEntry {
            protocol: proto,
            local_addr: local.to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: Arc::new(ProcessInfo {
                pid,
                name: name.to_string(),
                user: "alice".to_string(),
                uid: 1000,
                command: format!("/usr/bin/{}", name),
            }),
        }
    }

    #[test]
    fn test_sockets_run_success_table_and_json() {
        let platform = MockPlatform::with_sockets(vec![make_socket(
            12,
            "srv",
            "127.0.0.1:8080",
            Protocol::Tcp,
        )]);
        let filter = QueryFilter::default();
        assert!(run(&platform, &filter, false).is_ok());
        assert!(run(&platform, &filter, true).is_ok());
    }

    #[test]
    fn test_sockets_run_with_filters() {
        let platform = MockPlatform::with_sockets(vec![
            make_socket(12, "srv", "127.0.0.1:8080", Protocol::Tcp),
            make_socket(99, "dns", "127.0.0.1:5353", Protocol::Udp),
        ]);
        let filter = QueryFilter {
            tcp: true,
            ..QueryFilter::default()
        };
        assert!(run(&platform, &filter, true).is_ok());
    }
}
