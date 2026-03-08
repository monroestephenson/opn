use anyhow::Result;

use crate::model::QueryFilter;
use crate::platform::Platform;

pub fn run(_platform: &dyn Platform, _filter: &QueryFilter, _json: bool) -> Result<()> {
    anyhow::bail!("opn sockets: not yet implemented")
}
