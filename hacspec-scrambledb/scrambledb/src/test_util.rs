use crate::table::{Column, PlainTable};

pub fn generate_plain_table() -> PlainTable {
    let mut columns = Vec::new();
    columns.push(Column::new(
        String::from("Address"),
        vec![
            (
                String::from("Alice"),
                b"TestData1".to_vec(),
                //hash_to_curve::p256_hash::hash_to_curve(b"TestData1", b"sample_dst").unwrap(),
            ),
            (
                String::from("Bob"),
                b"TestData2".to_vec(),
                //hash_to_curve::p256_hash::hash_to_curve(b"TestData2", b"sample_dst").unwrap(),
            ),
        ],
    ));

    columns.push(Column::new(
        String::from("Date of Birth"),
        vec![
            (
                String::from("Alice"),
                b"TestData3".to_vec(),
                //hash_to_curve::p256_hash::hash_to_curve(b"TestData3", b"sample_dst").unwrap(),
            ),
            (
                String::from("Bob"),
                b"TestData4".to_vec(),
                //hash_to_curve::p256_hash::hash_to_curve(b"TestData4", b"sample_dst").unwrap(),
            ),
        ],
    ));

    columns.push(Column::new(
        String::from("Favorite Color"),
        vec![
            (
                String::from("Alice"),
                b"TestData5".to_vec(),
                //hash_to_curve::p256_hash::hash_to_curve(b"TestData5", b"sample_dst").unwrap(),
            ),
            (
                String::from("Bob"),
                b"TestData6".to_vec(),
                //hash_to_curve::p256_hash::hash_to_curve(b"TestData6", b"sample_dst").unwrap(),
            ),
        ],
    ));

    PlainTable::new(String::from("ExampleTable"), columns)
}
