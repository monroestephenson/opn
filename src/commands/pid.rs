use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::model::{OpenFile, QueryFilter};
use crate::platform::Platform;
use crate::render;
use crate::render::tree::TreeNode;
use crate::render::RenderOutcome;

fn matches_pid_filters(entry: &OpenFile, filter: &QueryFilter) -> bool {
    if let Some(filter_pid) = filter.pid {
        if entry.process.pid != filter_pid {
            return false;
        }
    }
    if let Some(user) = &filter.user {
        if entry.process.user != *user {
            return false;
        }
    }
    if let Some(process_name) = &filter.process_name {
        if entry.process.name != *process_name {
            return false;
        }
    }
    true
}

fn filter_is_set(filter: &QueryFilter) -> bool {
    filter.pid.is_some()
        || filter.user.is_some()
        || filter.process_name.is_some()
        || filter.state.is_some()
        || filter.tcp
        || filter.udp
        || filter.ipv4
        || filter.ipv6
        || filter.all
}

fn build_tree(
    pid: u32,
    name_map: &HashMap<u32, String>,
    children_map: &HashMap<u32, Vec<u32>>,
    depth: usize,
) -> TreeNode {
    let name = name_map
        .get(&pid)
        .cloned()
        .unwrap_or_else(|| format!("{} (gone)", pid));

    let child_pids = children_map.get(&pid);
    if child_pids.is_none() || child_pids.unwrap().is_empty() {
        return TreeNode {
            label: format!("{} ({})", name, pid),
            children: vec![],
        };
    }

    if depth == 0 {
        let n = child_pids.unwrap().len();
        return TreeNode {
            label: format!("{} ({}) ... ({} more levels)", name, pid, n),
            children: vec![],
        };
    }

    let mut children = Vec::new();
    for &child_pid in child_pids.unwrap() {
        children.push(build_tree(child_pid, name_map, children_map, depth - 1));
    }
    TreeNode {
        label: format!("{} ({})", name, pid),
        children,
    }
}

pub fn run(
    platform: &dyn Platform,
    pid: u32,
    filter: &QueryFilter,
    json: bool,
    tree: bool,
    depth: usize,
) -> Result<RenderOutcome> {
    if tree {
        if filter_is_set(filter) {
            anyhow::bail!("--tree cannot be combined with filter flags. Use opn pid <pid> --tree without filters.");
        }
        if depth == 0 || depth > 50 {
            anyhow::bail!("--depth must be between 1 and 50");
        }

        let table = platform.process_table()?;
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut name_map: HashMap<u32, String> = HashMap::new();
        for row in &table {
            children_map.entry(row.ppid).or_default().push(row.pid);
            name_map.insert(row.pid, row.name.clone());
        }

        if !name_map.contains_key(&pid) {
            anyhow::bail!("PID {} not found", pid);
        }

        let root = build_tree(pid, &name_map, &children_map, depth);
        if json {
            println!("{}", serde_json::to_string_pretty(&root)?);
        } else {
            print!("PROCESS TREE\n{}", render::tree::render_tree(&root));
        }
        return Ok(RenderOutcome::HasResults);
    }

    // Non-tree path: existing logic.
    let known_pids = platform.list_pids(&QueryFilter::default())?;
    if !known_pids.contains(&pid) {
        anyhow::bail!("PID {} not found", pid);
    }

    let mut entries = platform
        .list_open_files(pid)
        .with_context(|| format!("Failed to inspect open files for PID {}", pid))?;
    entries.retain(|entry| matches_pid_filters(entry, filter));

    Ok(render::render(&entries, json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FdType, ProcessInfo, ProcessTableRow};
    use crate::platform::mock::MockPlatform;
    use std::sync::Arc;

    fn make_file(pid: u32, process_name: &str, user: &str, path: &str) -> OpenFile {
        OpenFile {
            process: Arc::new(ProcessInfo {
                pid,
                name: process_name.to_string(),
                user: user.to_string(),
                uid: 1000,
                command: format!("/usr/bin/{}", process_name),
            }),
            fd: Some(3),
            fd_type: FdType::RegularFile,
            path: path.to_string(),
            deleted: false,
            socket_info: None,
        }
    }

    fn row(pid: u32, ppid: u32, name: &str) -> ProcessTableRow {
        ProcessTableRow {
            pid,
            ppid,
            name: name.to_string(),
        }
    }

    #[test]
    fn test_matches_pid_filters() {
        let file = make_file(42, "vim", "alice", "/tmp/a.txt");
        let filter = QueryFilter {
            pid: Some(42),
            user: Some("alice".to_string()),
            process_name: Some("vim".to_string()),
            ..QueryFilter::default()
        };
        assert!(matches_pid_filters(&file, &filter));
    }

    #[test]
    fn test_matches_pid_filters_rejects_pid_user_process_mismatch() {
        let file = make_file(42, "vim", "alice", "/tmp/a.txt");

        let pid_filter = QueryFilter {
            pid: Some(7),
            ..QueryFilter::default()
        };
        assert!(!matches_pid_filters(&file, &pid_filter));

        let user_filter = QueryFilter {
            user: Some("bob".to_string()),
            ..QueryFilter::default()
        };
        assert!(!matches_pid_filters(&file, &user_filter));

        let process_filter = QueryFilter {
            process_name: Some("nano".to_string()),
            ..QueryFilter::default()
        };
        assert!(!matches_pid_filters(&file, &process_filter));
    }

    #[test]
    fn test_run_pid_not_found() {
        let platform = MockPlatform::with_pids(vec![1, 2, 3]);
        let err = run(&platform, 9999, &QueryFilter::default(), false, false, 10).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_run_pid_success_table_and_json() {
        let platform = MockPlatform::with_files(vec![make_file(42, "vim", "alice", "/tmp/a.txt")]);
        let filter = QueryFilter::default();

        assert!(run(&platform, 42, &filter, false, false, 10).is_ok());
        assert!(run(&platform, 42, &filter, true, false, 10).is_ok());
    }

    #[test]
    fn test_run_pid_with_filters() {
        let platform = MockPlatform::with_files(vec![
            make_file(42, "vim", "alice", "/tmp/a.txt"),
            make_file(42, "vim", "bob", "/tmp/b.txt"),
        ]);

        let user_filter = QueryFilter {
            user: Some("alice".to_string()),
            ..QueryFilter::default()
        };
        assert!(run(&platform, 42, &user_filter, false, false, 10).is_ok());

        let pid_filter = QueryFilter {
            pid: Some(7),
            ..QueryFilter::default()
        };
        assert!(run(&platform, 42, &pid_filter, true, false, 10).is_ok());
    }

    #[test]
    fn test_tree_nonexistent_pid() {
        let platform = MockPlatform::with_process_table(vec![row(1, 0, "launchd")]);
        let err = run(&platform, 9999, &QueryFilter::default(), false, true, 10).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_tree_rejects_filters() {
        let platform = MockPlatform::with_process_table(vec![row(1, 0, "launchd")]);
        let filter = QueryFilter {
            all: true,
            ..QueryFilter::default()
        };
        let err = run(&platform, 1, &filter, false, true, 10).unwrap_err();
        assert!(err.to_string().contains("--tree cannot be combined"));
    }

    #[test]
    fn test_tree_linear_chain() {
        let platform = MockPlatform::with_process_table(vec![
            row(1, 0, "launchd"),
            row(50, 1, "sshd"),
            row(999, 50, "nginx"),
        ]);
        let result = run(&platform, 1, &QueryFilter::default(), false, true, 10);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tree_depth_limit_truncates() {
        // 1 -> 2 -> 3, depth=2 means show 1,2 and truncate 3's children
        let platform = MockPlatform::with_process_table(vec![
            row(1, 0, "root"),
            row(2, 1, "child"),
            row(3, 2, "grandchild"),
            row(4, 3, "greatgrandchild"),
        ]);
        let root = {
            let table = platform.process_table().unwrap();
            let mut cmap: HashMap<u32, Vec<u32>> = HashMap::new();
            let mut nmap: HashMap<u32, String> = HashMap::new();
            for r in &table {
                cmap.entry(r.ppid).or_default().push(r.pid);
                nmap.insert(r.pid, r.name.clone());
            }
            build_tree(1, &nmap, &cmap, 2)
        };
        let out = render::tree::render_tree(&root);
        assert!(out.contains("root (1)"));
        assert!(out.contains("child (2)"));
        assert!(out.contains("grandchild (3)"));
        assert!(out.contains("more levels"));
    }

    #[test]
    fn test_tree_exact_snapshot() {
        let platform = MockPlatform::with_process_table(vec![
            row(1, 0, "root"),
            row(2, 1, "child-a"),
            row(3, 1, "child-b"),
            row(4, 2, "grandchild"),
        ]);
        let root = {
            let table = platform.process_table().unwrap();
            let mut cmap: HashMap<u32, Vec<u32>> = HashMap::new();
            let mut nmap: HashMap<u32, String> = HashMap::new();
            for r in &table {
                cmap.entry(r.ppid).or_default().push(r.pid);
                nmap.insert(r.pid, r.name.clone());
            }
            build_tree(1, &nmap, &cmap, 10)
        };
        let out = render::tree::render_tree(&root);
        assert_eq!(
            out,
            "  root (1)\n  ├─ child-a (2)\n  │   └─ grandchild (4)\n  └─ child-b (3)\n"
        );
    }
}
