use serde::Serialize;

pub fn print_json<T: Serialize>(items: &[T]) {
    match serde_json::to_string_pretty(items) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing to JSON: {}", e),
    }
}
