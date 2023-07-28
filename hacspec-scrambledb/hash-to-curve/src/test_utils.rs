use serde_json::Value;

pub fn load_vectors(path: &str) -> Value {
    use std::fs;
    serde_json::from_str(&fs::read_to_string(path).expect("File not found.")).unwrap()
}
