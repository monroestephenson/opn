use std::io::{self, Write};

pub trait Tabular {
    fn headers() -> Vec<&'static str>;
    fn row(&self) -> Vec<String>;
}

fn write_table<T: Tabular>(items: &[T], mut w: impl Write) -> io::Result<()> {
    let headers = T::headers();
    let rows: Vec<Vec<String>> = items.iter().map(|item| item.row()).collect();
    let num_cols = headers.len();
    let mut widths = vec![0usize; num_cols];

    for (i, header) in headers.iter().enumerate() {
        widths[i] = header.len();
    }
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i < num_cols {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Header
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
        .collect();
    writeln!(w, "{}", header_line.join("  "))?;

    // Separator
    let sep: Vec<String> = widths.iter().map(|&w| "-".repeat(w)).collect();
    writeln!(w, "{}", sep.join("  "))?;

    // Rows
    for row in &rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                if i < num_cols {
                    format!("{:<width$}", cell, width = widths[i])
                } else {
                    cell.clone()
                }
            })
            .collect();
        writeln!(w, "{}", line.join("  "))?;
    }

    Ok(())
}

pub fn print_table<T: Tabular>(items: &[T]) {
    if items.is_empty() {
        eprintln!("No results found.");
        return;
    }
    write_table(items, io::stdout().lock()).expect("failed to write table to stdout");
}

#[cfg(test)]
pub fn format_table<T: Tabular>(items: &[T]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut buf = Vec::new();
    write_table(items, &mut buf).expect("failed to write table to buffer");
    String::from_utf8(buf).expect("table output should be valid UTF-8")
}
