//! ## Tables and Data Types
//! The `ScrambleDB` protocol provides conversions between types of data
//! tables that are differentiated by their structure and contents.

#[derive(Debug, Clone)]
pub struct Table<T> {
    identifier: String,
    data: Vec<T>,
}

impl<T> Table<T> {
    /// Create a new table.
    pub fn new(identifier: String, data: Vec<T>) -> Self {
        Self { identifier, data }
    }

    /// Get the identifier (name) of this table.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Get the table entries.
    pub fn data(&self) -> &[T] {
        self.data.as_ref()
    }

    /// Sort the table by its handles.
    pub fn sort(&mut self)
    where
        T: Ord,
    {
        self.data.sort()
    }
}
