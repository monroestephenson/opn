use anyhow::Result;
use serde::Serialize;

use crate::model::{ProcessAncestor, ProcessInfo};
use crate::platform::Platform;
use crate::render::RenderOutcome;

#[derive(Serialize)]
struct AncestryResult {
    pid: u32,
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ancestry: Vec<ProcessAncestor>,
}

fn format_tree(target: &ProcessInfo, ancestry: &[ProcessAncestor]) -> String {
    let mut out = String::from("PROCESS TREE\n");
    if ancestry.is_empty() {
        out.push_str(&format!("  {} ({})\n", target.name, target.pid));
        return out;
    }
    // Root ancestor — no connector
    out.push_str(&format!("  {} ({})\n", ancestry[0].name, ancestry[0].pid));
    // Remaining ancestors — connector at parent depth
    for (i, ancestor) in ancestry.iter().enumerate().skip(1) {
        let indent = "  ".repeat(i);
        out.push_str(&format!("  {}└─ {} ({})\n", indent, ancestor.name, ancestor.pid));
    }
    // Target process — connector at last ancestor's depth
    let indent = "  ".repeat(ancestry.len());
    out.push_str(&format!(
        "  {}└─ {} ({}) ←\n",
        indent, target.name, target.pid
    ));
    out
}

pub fn run(platform: &dyn Platform, pid: u32, json: bool) -> Result<RenderOutcome> {
    let target = platform
        .process_info(pid)
        .map_err(|_| anyhow::anyhow!("PID {} not found", pid))?;
    let ancestry = platform.process_ancestry(pid)?;

    if json {
        let result = AncestryResult {
            pid,
            name: target.name.clone(),
            ancestry,
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", format_tree(&target, &ancestry));
    }

    Ok(RenderOutcome::HasResults)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcessInfo;
    use crate::platform::mock::MockPlatform;

    fn proc_info(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            user: "u".to_string(),
            uid: 1000,
            command: format!("/usr/bin/{name}"),
        }
    }

    fn ancestor(pid: u32, name: &str) -> ProcessAncestor {
        ProcessAncestor {
            pid,
            name: name.to_string(),
        }
    }

    #[test]
    fn test_ancestry_pid_not_found() {
        let platform = MockPlatform::with_pids(vec![1, 2, 3]);
        let err = run(&platform, 9999, false).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_ancestry_found_table() {
        let platform = MockPlatform::with_pids(vec![42]);
        let result = run(&platform, 42, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ancestry_found_json() {
        let platform = MockPlatform::with_pids(vec![42]);
        let result = run(&platform, 42, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_format_tree_with_ancestry() {
        let target = proc_info(999, "nginx");
        let chain = vec![ancestor(1, "launchd"), ancestor(50, "sshd")];
        let tree = format_tree(&target, &chain);
        assert!(tree.contains("PROCESS TREE"));
        assert!(tree.contains("launchd"));
        assert!(tree.contains("sshd"));
        assert!(tree.contains("nginx"));
        assert!(tree.contains("└─"));
        assert!(tree.contains("←"));
    }

    #[test]
    fn test_format_tree_no_ancestry() {
        let target = proc_info(1, "launchd");
        let tree = format_tree(&target, &[]);
        assert!(tree.contains("PROCESS TREE"));
        assert!(tree.contains("launchd"));
        assert!(!tree.contains("└─"));
        assert!(!tree.contains("←"));
    }
}
