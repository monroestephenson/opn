use anyhow::Result;

use crate::model::{OpenFile, QueryFilter};
use crate::platform::Platform;
use crate::render;
use crate::render::table::Tabular;

impl Tabular for OpenFile {
    fn headers() -> Vec<&'static str> {
        vec!["PID", "PROCESS", "USER", "FD", "TYPE", "PATH"]
    }

    fn row(&self) -> Vec<String> {
        let path_display = if self.deleted {
            format!("{} (deleted)", self.path)
        } else {
            self.path.clone()
        };
        vec![
            self.process.pid.to_string(),
            self.process.name.clone(),
            self.process.user.clone(),
            self.fd.to_string(),
            self.fd_type.to_string(),
            path_display,
        ]
    }
}

pub fn run(platform: &dyn Platform, path: &str, filter: &QueryFilter, json: bool) -> Result<()> {
    let entries = platform.find_by_file(path, filter)?;
    render::render(&entries, json);
    Ok(())
}
