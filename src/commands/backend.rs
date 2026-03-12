use anyhow::Result;

use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn run(platform: &dyn Platform, json: bool) -> Result<RenderOutcome> {
    let status = platform.backend_status()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("BACKEND      {}", status.backend);
        println!("READY        {}", yes_no(status.ready));
        println!(
            "LIVE EVENTS  {}",
            yes_no(status.supports_live_socket_activity)
        );
        println!("STRICT LIVE  {}", yes_no(status.strict_live_mode));
        println!("RUNNING ROOT {}", yes_no(status.running_as_root));
        println!("TRACKED      {}", status.tracked_flow_count);
        println!(
            "OBJECT       {}",
            status.object_path.as_deref().unwrap_or("-")
        );
        println!(
            "INTERFACE    {}",
            status.interface.as_deref().unwrap_or("-")
        );
        if let Some(error) = &status.load_error {
            println!("LOAD ERROR   {}", error);
        }

        if status.backend == "ebpf" && status.ready && status.tracked_flow_count == 0 {
            println!();
            println!(
                "Tip: eBPF is loaded but the tracked flow table is empty. Run `opn watch` or \
                 `opn history record` and generate socket activity, or `opn sockets` once to seed it from a procfs snapshot."
            );
        }
    }

    Ok(RenderOutcome::HasResults)
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
