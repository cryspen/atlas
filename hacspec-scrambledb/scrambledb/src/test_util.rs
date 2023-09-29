use crate::table::{Column, PlainTable};

pub fn generate_plain_table() -> PlainTable {
    let mut columns = Vec::new();
    columns.push(Column::new(
        String::from("Address"),
        vec![
            (String::from("Alice"), b"TestData1".to_vec()),
            (String::from("Bob"), b"TestData2".to_vec()),
        ],
    ));

    columns.push(Column::new(
        String::from("Date of Birth"),
        vec![
            (String::from("Alice"), b"TestData3".to_vec()),
            (String::from("Bob"), b"TestData4".to_vec()),
        ],
    ));

    columns.push(Column::new(
        String::from("Favorite Color"),
        vec![
            (String::from("Alice"), b"TestData5".to_vec()),
            (String::from("Bob"), b"TestData6".to_vec()),
        ],
    ));

    PlainTable::new(String::from("ExampleTable"), columns)
}
