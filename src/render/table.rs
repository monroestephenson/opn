pub trait Tabular {
    fn headers() -> Vec<&'static str>;
    fn row(&self) -> Vec<String>;
}

pub fn print_table<T: Tabular>(items: &[T]) {
    if items.is_empty() {
        eprintln!("No results found.");
        return;
    }

    let headers = T::headers();
    let rows: Vec<Vec<String>> = items.iter().map(|item| item.row()).collect();

    // Calculate column widths
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

    // Print header
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
        .collect();
    println!("{}", header_line.join("  "));

    // Print separator
    let sep: Vec<String> = widths.iter().map(|&w| "-".repeat(w)).collect();
    println!("{}", sep.join("  "));

    // Print rows
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
        println!("{}", line.join("  "));
    }
}
