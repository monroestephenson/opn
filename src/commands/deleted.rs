use anyhow::Result;

use crate::model::QueryFilter;
use crate::platform::Platform;
use crate::render;
use crate::render::RenderOutcome;

pub fn run(platform: &dyn Platform, filter: &QueryFilter, json: bool) -> Result<RenderOutcome> {
    let entries = platform.find_deleted(filter)?;
    Ok(render::render(&entries, json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FdType, OpenFile, ProcessInfo};
    use crate::platform::mock::MockPlatform;
    use std::sync::Arc;

    fn make_deleted_file(pid: u32, user: &str, process_name: &str, path: &str) -> OpenFile {
        OpenFile {
            process: Arc::new(ProcessInfo {
                pid,
                name: process_name.to_string(),
                user: user.to_string(),
                uid: 1000,
                command: format!("/usr/bin/{}", process_name),
            }),
            fd: Some(7),
            fd_type: FdType::RegularFile,
            path: path.to_string(),
            deleted: true,
            socket_info: None,
        }
    }

    #[test]
    fn test_deleted_run_success_table_and_json() {
        let platform = MockPlatform::with_files(vec![make_deleted_file(
            101,
            "alice",
            "worker",
            "/tmp/log.txt",
        )]);
        let filter = QueryFilter::default();
        assert!(run(&platform, &filter, false).is_ok());
        assert!(run(&platform, &filter, true).is_ok());
    }
}
