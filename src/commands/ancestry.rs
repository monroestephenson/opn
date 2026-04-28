use anyhow::Result;
use serde::Serialize;

use crate::model::{ProcessAncestor, ProcessInfo};
use crate::platform::Platform;
use crate::render;
use crate::render::tree::TreeNode;
use crate::render::RenderOutcome;

#[derive(Serialize)]
struct AncestryResult {
    pid: u32,
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ancestry: Vec<ProcessAncestor>,
}

fn build_ancestry_tree(target: &ProcessInfo, ancestry: &[ProcessAncestor]) -> TreeNode {
    if ancestry.is_empty() {
        return TreeNode {
            label: format!("{} ({})", target.name, target.pid),
            children: vec![],
        };
    }
    // Build chain from root-most ancestor down to target.
    // target is the deepest node, marked with ←.
    let mut node = TreeNode {
        label: format!("{} ({}) ←", target.name, target.pid),
        children: vec![],
    };
    for ancestor in ancestry.iter().rev() {
        node = TreeNode {
            label: format!("{} ({})", ancestor.name, ancestor.pid),
            children: vec![node],
        };
    }
    node
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
        let root = build_ancestry_tree(&target, &ancestry);
        print!("PROCESS TREE\n{}", render::tree::render_tree(&root));
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
    fn test_build_ancestry_tree_with_chain() {
        let target = proc_info(999, "nginx");
        let chain = vec![ancestor(1, "launchd"), ancestor(50, "sshd")];
        let root = build_ancestry_tree(&target, &chain);
        let out = render::tree::render_tree(&root);
        assert_eq!(out, "  launchd (1)\n  └─ sshd (50)\n    └─ nginx (999) ←\n");
    }

    #[test]
    fn test_build_ancestry_tree_no_ancestry() {
        let target = proc_info(1, "launchd");
        let root = build_ancestry_tree(&target, &[]);
        let out = render::tree::render_tree(&root);
        assert_eq!(out, "  launchd (1)\n");
    }
}
