pub mod table;
pub mod json;

use serde::Serialize;

use crate::render::table::Tabular;

pub fn render<T: Tabular + Serialize>(items: &[T], as_json: bool) {
    if as_json {
        json::print_json(items);
    } else {
        table::print_table(items);
    }
}
