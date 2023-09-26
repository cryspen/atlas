use hacspec_lib::Randomness;
use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;
use web_sys::HtmlTableRowElement;
use web_sys::{Document, HtmlTableElement};

use crate::table::BlindIdentifier;
use crate::table::Column;
use crate::table::ConvertedTable;
use crate::table::EncryptedValue;
use crate::table::MultiColumnTable;
use crate::table::Pseudonym;
use crate::table::SingleColumnTable;
use crate::{
    setup::{ConverterContext, StoreContext},
    table::{BlindTable, PlainTable, PseudonymizedTable},
};
use std::collections::HashMap;
use std::fmt::Debug;

use gloo_utils::format::JsValueSerdeExt;

#[wasm_bindgen]
pub fn demo_blind_table() {}

#[wasm_bindgen]
pub fn init_table(table: JsValue) {
    let table: String = table.into_serde().unwrap();
    let table: serde_json::Value = serde_json::from_str(&table).unwrap();
    run(table)
}

pub fn generate_plain_table(
    table: serde_json::Value,
) -> (PlainTable, HashMap<p256::P256Point, String>) {
    let mut columns = Vec::new();
    let mut values = HashMap::new();
    let column_names = ["Address", "Date of Birth", "Favourite Color"];
    for column in column_names {
        let mut column_values = vec![];
        for i in 0..table.as_array().unwrap().len() {
            let row = &table[i];

            let encoded_value = hash_to_curve::p256_hash::hash_to_curve(
                row[column].as_str().unwrap().as_bytes(),
                b"sample_dst",
            )
            .unwrap();
            values.insert(
                encoded_value.clone(),
                String::from(row[column].as_str().unwrap()),
            );
            column_values.push((row["Identity"].as_str().unwrap().to_string(), encoded_value));
        }
        columns.push(Column::new(column.to_string(), column_values));
    }

    (
        PlainTable::new(String::from("ExampleTable"), columns),
        values,
    )
}

pub fn run(table: serde_json::Value) {
    use rand::prelude::*;

    let mut rng = rand::thread_rng();
    let mut randomness = [0u8; 1000000];
    rng.fill_bytes(&mut randomness);
    let mut randomness = Randomness::new(randomness.to_vec());

    // Setup and Source input
    let (source_table, values) = generate_plain_table(table);

    let converter_context = ConverterContext::setup(&mut randomness).unwrap();

    let lake_context = StoreContext::setup(&mut randomness).unwrap();
    let (ek_lake, bpk_lake) = lake_context.public_keys();

    let processor_context = StoreContext::setup(&mut randomness).unwrap();
    let (ek_processor, bpk_processor) = processor_context.public_keys();

    // Split conversion
    let blind_source_table = crate::split::prepare_split_conversion(
        ek_lake,
        bpk_lake,
        source_table.clone(),
        &mut randomness,
    )
    .unwrap();

    let blind_split_tables = crate::split::split_conversion(
        &converter_context,
        bpk_lake,
        ek_lake,
        blind_source_table.clone(),
        &mut randomness,
    )
    .unwrap();

    let finalized_split_tables =
        crate::finalize::finalize_conversion(&lake_context, blind_split_tables.clone()).unwrap();

    // Join conversion
    let join_table_selection = vec![
        finalized_split_tables[0].clone(),
        finalized_split_tables[1].clone(),
    ];

    let blind_pre_join_tables = crate::join::prepare_join_conversion(
        &lake_context,
        bpk_processor,
        ek_processor,
        join_table_selection.clone(),
        &mut randomness,
    )
    .unwrap();

    let blind_joined_tables = crate::join::join_conversion(
        &converter_context,
        bpk_processor,
        ek_processor,
        blind_pre_join_tables.clone(),
        &mut randomness,
    )
    .unwrap();

    let joined_tables =
        crate::finalize::finalize_conversion(&processor_context, blind_joined_tables.clone())
            .unwrap();

    // == Visualization ==

    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");

    // == Data Source ==
    // let source_table_dom =
    //     dom_insert_multicolumn_table(&"data-source-table-plain", &source_table, &document);
    // fill_plain_table(&source_table_dom, &source_table);

    // == Blind Table for Pseudonymization ==
    let converter_input_1 = dom_insert_multicolumn_table_single_id(
        &"converter-input-1",
        &blind_source_table,
        &document,
    );
    fill_blind_table_single_id(&converter_input_1, &blind_source_table);

    // == Blind Pseudonymized Table ==
    for converted_table in blind_split_tables.iter() {
        let table_element =
            dom_insert_column_table(&"converter-output-1", &converted_table, &document);
        fill_blind_column(&table_element, converted_table);
    }

    // == Unblinded Pseudonymized Table ==
    for lake_table in finalized_split_tables.iter() {
        let lake_table_element =
            dom_insert_column_table(&"data-lake-tables", &lake_table, &document);
        fill_pseudonymized_column(&lake_table_element, lake_table, &values);
    }

    // select first two lake tables for join
    for table in blind_pre_join_tables.iter() {
        let converter_input_2 =
            dom_insert_multicolumn_table(&"converter-input-2", &table, &document);
        fill_blind_table(&converter_input_2, &table);
    }

    for table in blind_joined_tables.iter() {
        let converter_output_2 = dom_insert_column_table(&"converter-output-2", &table, &document);
        fill_blind_column(&converter_output_2, &table);
    }

    for lake_table in joined_tables.iter() {
        let lake_table_element =
            dom_insert_column_table(&"data-processor-joined", &lake_table, &document);
        fill_pseudonymized_column(&lake_table_element, lake_table, &values);
    }
}

// Create a table skeleton for pseudonymous table
fn dom_insert_column_table<K: Debug + Clone, V: Debug + Clone>(
    element_id: &str,
    table: &SingleColumnTable<K, V>,
    document: &Document,
) -> HtmlTableElement {
    let table_div = document.get_element_by_id(element_id).unwrap();

    let table_element: HtmlTableElement = document
        .create_element("table")
        .unwrap()
        .dyn_into::<web_sys::HtmlTableElement>()
        .unwrap();

    let t_head = table_element.create_t_head();

    let header_row = document
        .create_element("tr")
        .unwrap()
        .dyn_into::<web_sys::HtmlTableRowElement>()
        .unwrap();
    header_row.set_attribute("class", "tableheader").unwrap();

    let id_cell = header_row.insert_cell().unwrap();
    id_cell.set_text_content(Some(&"ID"));
    let header_cell = header_row.insert_cell().unwrap();
    header_cell.set_text_content(Some(&table.column().attribute()));

    t_head.append_child(&header_row).unwrap();

    table_div.append_child(&table_element).unwrap();
    table_element
}

// creates a table skeleton for a multicolumn table.
fn dom_insert_multicolumn_table<K: Debug, V: Debug>(
    element_id: &str,
    table: &MultiColumnTable<K, V>,
    document: &Document,
) -> HtmlTableElement
where
    K: Clone,
    V: Clone,
{
    let table_div = document.get_element_by_id(element_id).unwrap();

    let table_element: HtmlTableElement = document
        .create_element("table")
        .unwrap()
        .dyn_into::<web_sys::HtmlTableElement>()
        .unwrap();

    let t_head = table_element.create_t_head();

    let header_row = document
        .create_element("tr")
        .unwrap()
        .dyn_into::<web_sys::HtmlTableRowElement>()
        .unwrap();
    header_row.set_attribute("class", "tableheader").unwrap();

    for colum in table.columns() {
        let id_cell = header_row.insert_cell().unwrap();
        id_cell.set_text_content(Some(&"ID"));
        let header_cell = header_row.insert_cell().unwrap();
        header_cell.set_text_content(Some(&colum.attribute()));
    }

    t_head.append_child(&header_row).unwrap();

    table_div.append_child(&table_element).unwrap();
    table_element
}

// creates a table skeleton for a multicolumn table where only the first id column is shown.
fn dom_insert_multicolumn_table_single_id<K: Debug, V: Debug>(
    element_id: &str,
    table: &MultiColumnTable<K, V>,
    document: &Document,
) -> HtmlTableElement
where
    K: Clone,
    V: Clone,
{
    let table_div = document.get_element_by_id(element_id).unwrap();

    let table_element: HtmlTableElement = document
        .create_element("table")
        .unwrap()
        .dyn_into::<web_sys::HtmlTableElement>()
        .unwrap();

    let t_head = table_element.create_t_head();

    let header_row = document
        .create_element("tr")
        .unwrap()
        .dyn_into::<web_sys::HtmlTableRowElement>()
        .unwrap();
    header_row.set_attribute("class", "tableheader").unwrap();

    let id_cell = header_row.insert_cell().unwrap();
    id_cell.set_text_content(Some(&"ID"));

    for colum in table.columns() {
        let header_cell = header_row.insert_cell().unwrap();
        header_cell.set_text_content(Some(&colum.attribute()));
    }

    t_head.append_child(&header_row).unwrap();

    table_div.append_child(&table_element).unwrap();
    table_element
}
// fn fill_plain_table(table_element: &HtmlTableElement, plain_table: &PlainTable) {
//     for row in plain_table.rows() {
//         let html_row = table_element
//             .insert_row()
//             .unwrap()
//             .dyn_into::<web_sys::HtmlTableRowElement>()
//             .unwrap();
//         for (key, value) in row {
//             insert_cell(&html_row, TableCell::PlainID(key));
//             insert_cell(&html_row, TableCell::PlainValue(value));
//         }
//     }
// }

fn fill_blind_table(table_element: &HtmlTableElement, blind_table: &BlindTable) {
    for row in blind_table.rows() {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();

        for (key, value) in row {
            insert_cell(&html_row, TableCell::BlindID(key));
            insert_cell(&html_row, TableCell::BlindValue(value));
        }
    }
}

fn fill_blind_table_single_id(table_element: &HtmlTableElement, blind_table: &BlindTable) {
    for row in blind_table.rows() {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();

        insert_cell(&html_row, TableCell::BlindID(row[0].0));
        insert_cell(&html_row, TableCell::BlindValue(row[0].1));

        for (_key, value) in row.iter().skip(1) {
            insert_cell(&html_row, TableCell::BlindValue(*value));
        }
    }
}

fn fill_pseudonymized_column(
    table_element: &HtmlTableElement,
    table: &PseudonymizedTable,
    values: &HashMap<p256::P256Point, String>,
) {
    for (key, value) in table.column().data() {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();

        insert_cell(&html_row, TableCell::Pseudonym(key));
        insert_cell(
            &html_row,
            TableCell::PlainValue(values.get(&value).unwrap().clone()),
        );
    }
}

fn fill_blind_column(table_element: &HtmlTableElement, table: &ConvertedTable) {
    for (key, value) in table.column().data() {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();

        insert_cell(&html_row, TableCell::BlindID(key));
        insert_cell(&html_row, TableCell::BlindValue(value));
    }
}

enum TableCell {
    PlainValue(String),
    BlindID(BlindIdentifier),
    BlindValue(EncryptedValue),
    Pseudonym(Pseudonym),
}

impl TableCell {
    fn to_string(&self) -> String {
        match &self {
            TableCell::PlainValue(v) => v.clone(),
            TableCell::BlindID(b) => String::from(format!(
                "BLIND-ID({}..., {}...)",
                &hex::encode(b.0.raw_bytes())[0..5],
                &hex::encode(b.1.raw_bytes())[0..5],
            )),
            TableCell::BlindValue(b) => {
                format!(
                    "ENC({}..., {}...)",
                    &hex::encode(b.0.raw_bytes())[0..5],
                    &hex::encode(b.1.raw_bytes())[0..5],
                )
            }
            TableCell::Pseudonym(nym) => {
                String::from(format!("NYM({}...)", &hex::encode(nym)[0..5]))
            }
        }
    }
}

fn insert_cell(row: &HtmlTableRowElement, value: TableCell) {
    let cell = row.insert_cell().unwrap();
    cell.set_text_content(Some(&value.to_string()));
}
