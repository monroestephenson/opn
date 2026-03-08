use anyhow::Result;

use crate::model::QueryFilter;
use crate::platform::Platform;

pub fn run(_platform: &dyn Platform, _pid: u32, _filter: &QueryFilter, _json: bool) -> Result<()> {
    anyhow::bail!("opn pid: not yet implemented")
}
