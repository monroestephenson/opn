use anyhow::{Context, Result};

use crate::model::{OpenFile, QueryFilter};
use crate::platform::Platform;
use crate::render;
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

pub fn run(
    platform: &dyn Platform,
    pid: u32,
    filter: &QueryFilter,
    json: bool,
) -> Result<RenderOutcome> {
    // Existence check first to return a clear error for invalid PIDs.
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
    use crate::model::{FdType, ProcessInfo};
    use crate::platform::mock::MockPlatform;

    fn make_file(pid: u32, process_name: &str, user: &str, path: &str) -> OpenFile {
        OpenFile {
            process: ProcessInfo {
                pid,
                name: process_name.to_string(),
                user: user.to_string(),
                uid: 1000,
                command: format!("/usr/bin/{}", process_name),
            },
            fd: 3,
            fd_type: FdType::RegularFile,
            path: path.to_string(),
            deleted: false,
            socket_info: None,
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
        let err = run(&platform, 9999, &QueryFilter::default(), false).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_run_pid_success_table_and_json() {
        let platform = MockPlatform::with_files(vec![make_file(42, "vim", "alice", "/tmp/a.txt")]);
        let filter = QueryFilter::default();

        assert!(run(&platform, 42, &filter, false).is_ok());
        assert!(run(&platform, 42, &filter, true).is_ok());
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
        assert!(run(&platform, 42, &user_filter, false).is_ok());

        let pid_filter = QueryFilter {
            pid: Some(7),
            ..QueryFilter::default()
        };
        assert!(run(&platform, 42, &pid_filter, true).is_ok());
    }
}
