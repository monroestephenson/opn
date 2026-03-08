pub mod table;
pub mod json;
#[cfg(test)]
mod tests;

use serde::Serialize;

use crate::render::table::Tabular;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderOutcome {
    HasResults,
    NoResults,
}

pub fn render<T: Tabular + Serialize>(items: &[T], as_json: bool) -> RenderOutcome {
    if as_json {
        json::print_json(items);
    } else {
        table::print_table(items);
    }
    if items.is_empty() {
        RenderOutcome::NoResults
    } else {
        RenderOutcome::HasResults
    }
}
