use anyhow::Result;

use crate::model::{OpenFile, QueryFilter};
use crate::platform::Platform;
use crate::render;
use crate::render::table::Tabular;
use crate::render::RenderOutcome;

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
        let fd_display = self.fd.map(|f| f.to_string()).unwrap_or_else(|| "-".into());
        vec![
            self.process.pid.to_string(),
            self.process.name.clone(),
            self.process.user.clone(),
            fd_display,
            self.fd_type.to_string(),
            path_display,
        ]
    }
}

pub fn run(
    platform: &dyn Platform,
    path: &str,
    filter: &QueryFilter,
    json: bool,
) -> Result<RenderOutcome> {
    crate::path_safety::validate_user_path(path)?;
    let entries = platform.find_by_file(path, filter)?;
    Ok(render::render(&entries, json))
}
