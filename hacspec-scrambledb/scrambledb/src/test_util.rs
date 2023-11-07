use crate::{
    data_types::{DataValue, IdentifiableData},
    table::Table,
};

pub fn generate_plain_table() -> Table<IdentifiableData> {
    let mut data = Vec::new();
    data.push(IdentifiableData {
        handle: "Alice".into(),
        data_value: DataValue {
            value: b"TestData1".to_vec(),
            attribute_name: "Address".into(),
        },
    });
    data.push(IdentifiableData {
        handle: "Bob".into(),
        data_value: DataValue {
            value: b"TestData2".to_vec(),
            attribute_name: "Address".into(),
        },
    });
    data.push(IdentifiableData {
        handle: "Alice".into(),
        data_value: DataValue {
            value: b"TestData3".to_vec(),
            attribute_name: "Date of Birth".into(),
        },
    });
    data.push(IdentifiableData {
        handle: "Bob".into(),
        data_value: DataValue {
            value: b"TestData4".to_vec(),
            attribute_name: "Date of Birth".into(),
        },
    });
    data.push(IdentifiableData {
        handle: "Alice".into(),
        data_value: DataValue {
            value: b"TestData5".to_vec(),
            attribute_name: "Favorite Color".into(),
        },
    });
    data.push(IdentifiableData {
        handle: "Bob".into(),
        data_value: DataValue {
            value: b"TestData6".to_vec(),
            attribute_name: "Favorite Color".into(),
        },
    });

    Table::new(String::from("ExampleTable"), data)
}
