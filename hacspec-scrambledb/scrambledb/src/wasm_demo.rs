use hacspec_lib::Randomness;
use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;

use web_sys::{Document, HtmlTableElement};

use crate::data_types::BlindedIdentifiableData;
use crate::data_types::BlindedIdentifiableHandle;
use crate::data_types::BlindedPseudonymizedData;
use crate::data_types::BlindedPseudonymizedHandle;
use crate::data_types::DataValue;
use crate::data_types::EncryptedDataValue;
use crate::data_types::FinalizedPseudonym;
use crate::data_types::IdentifiableData;
use crate::data_types::PseudonymizedData;
use crate::{
    setup::{ConverterContext, StoreContext},
    table::Table,
};

use std::fmt::Display;

use gloo_utils::format::JsValueSerdeExt;

#[wasm_bindgen]
pub fn demo_blind_table() {}

#[wasm_bindgen]
pub fn init_table(table: JsValue) {
    let table: String = table.into_serde().unwrap();
    let table: serde_json::Value = serde_json::from_str(&table).unwrap();
    run(table)
}

const DEMO_COLUMN_NAMES: [&str; 3] = ["Address", "Date of Birth", "Favourite Color"];

pub fn generate_plain_table(table: serde_json::Value) -> Table<IdentifiableData> {
    let mut data = Vec::new();
    for column in DEMO_COLUMN_NAMES {
        for i in 0..table.as_array().unwrap().len() {
            let row = &table[i];

            let encoded_value = row[column].as_str().unwrap().as_bytes().to_vec();

            data.push(IdentifiableData {
                handle: row["Identity"].as_str().unwrap().to_string(),
                data_value: DataValue {
                    value: encoded_value,
                    attribute_name: column.into(),
                },
            });
        }
    }

    Table::new("ExampleTable".into(), data)
}

pub fn run(table: serde_json::Value) {
    use rand::prelude::*;

    let mut rng = rand::thread_rng();
    let mut randomness = [0u8; 1000000];
    rng.fill_bytes(&mut randomness);
    let mut randomness = Randomness::new(randomness.to_vec());

    // Setup and Source input
    let source_table = generate_plain_table(table);

    let converter_context = ConverterContext::setup(&mut randomness).unwrap();

    let lake_context = StoreContext::setup(&mut randomness).unwrap();
    let (ek_lake, bpk_lake) = lake_context.public_keys();

    let processor_context = StoreContext::setup(&mut randomness).unwrap();
    let (ek_processor, bpk_processor) = processor_context.public_keys();

    // Split conversion
    let blind_source_table = crate::split::prepare_split_conversion(
        &ek_lake,
        bpk_lake,
        source_table.clone(),
        &mut randomness,
    )
    .unwrap();

    let blind_split_tables = crate::split::split_conversion(
        &converter_context,
        bpk_lake,
        &ek_lake,
        blind_source_table.clone(),
        &mut randomness,
    )
    .unwrap();

    let finalized_split_tables =
        crate::finalize::finalize_conversion(&lake_context, blind_split_tables.clone()).unwrap();

    // Join conversion
    let join_table_selection = Table::new(
        "Join".into(),
        finalized_split_tables
            .data()
            .iter()
            .filter_map(|entry| {
                if entry.data_value.attribute_name == DEMO_COLUMN_NAMES[0]
                    || entry.data_value.attribute_name == DEMO_COLUMN_NAMES[1]
                {
                    Some(entry.clone())
                } else {
                    None
                }
            })
            .collect(),
    );

    let blind_pre_join_tables = crate::join::prepare_join_conversion(
        &lake_context,
        bpk_processor,
        &ek_processor,
        join_table_selection.clone(),
        &mut randomness,
    )
    .unwrap();

    let blind_joined_tables = crate::join::join_conversion(
        &converter_context,
        bpk_processor,
        &ek_processor,
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

    for column in DEMO_COLUMN_NAMES {
        // Converter Input
        let converter_input_1 = dom_insert_column_table(&"converter-input-1", column, &document);
        fill_blind_column(
            &converter_input_1,
            blind_source_table
                .data()
                .iter()
                .filter(|entry| entry.encrypted_data_value.attribute_name == column)
                .collect(),
        );

        let converted_table_element =
            dom_insert_column_table(&"converter-output-1", column, &document);
        fill_blinded_pseudonymized_column(
            &converted_table_element,
            blind_split_tables
                .data()
                .iter()
                .filter(|entry| entry.encrypted_data_value.attribute_name == column)
                .collect(),
        );

        let lake_table_element = dom_insert_column_table(&"data-lake-tables", &column, &document);
        fill_pseudonymized_column(
            &lake_table_element,
            finalized_split_tables
                .data()
                .iter()
                .filter(|entry| entry.data_value.attribute_name == column)
                .collect(),
        );
    }

    for column in DEMO_COLUMN_NAMES[0..2].iter() {
        let converter_input_element_2 =
            dom_insert_column_table(&"converter-input-2", column, &document);

        fill_blinded_pseudonymized_column(
            &converter_input_element_2,
            blind_pre_join_tables
                .data()
                .iter()
                .filter(|entry| entry.encrypted_data_value.attribute_name == *column)
                .collect(),
        );

        let converter_output_element_2 =
            dom_insert_column_table(&"converter-output-2", column, &document);
        fill_blinded_pseudonymized_column(
            &converter_output_element_2,
            blind_joined_tables
                .data()
                .iter()
                .filter(|entry| entry.encrypted_data_value.attribute_name == *column)
                .collect(),
        );

        let lake_table_element =
            dom_insert_column_table(&"data-processor-joined", &column, &document);
        fill_pseudonymized_column(
            &lake_table_element,
            joined_tables
                .data()
                .iter()
                .filter(|entry| entry.data_value.attribute_name == *column)
                .collect(),
        );
    }
}

// Create a table skeleton for a table skeleton
fn dom_insert_column_table(
    element_id: &str,
    header: &str,
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
    header_cell.set_text_content(Some(header));

    t_head.append_child(&header_row).unwrap();

    table_div.append_child(&table_element).unwrap();
    table_element
}

fn fill_blind_column(table_element: &HtmlTableElement, table_data: Vec<&BlindedIdentifiableData>) {
    for blinded_data in table_data {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();

        let cell = html_row.insert_cell().unwrap();
        cell.set_text_content(Some(&blinded_data.blinded_handle.to_string()));

        let cell = html_row.insert_cell().unwrap();
        cell.set_text_content(Some(&blinded_data.encrypted_data_value.to_string()));
    }
}

fn fill_blinded_pseudonymized_column(
    table_element: &HtmlTableElement,
    table_data: Vec<&BlindedPseudonymizedData>,
) {
    for blinded_data in table_data {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();

        let cell = html_row.insert_cell().unwrap();
        cell.set_text_content(Some(&blinded_data.blinded_handle.to_string()));

        let cell = html_row.insert_cell().unwrap();
        cell.set_text_content(Some(&blinded_data.encrypted_data_value.to_string()));
    }
}

fn fill_pseudonymized_column(
    table_element: &HtmlTableElement,
    table_data: Vec<&PseudonymizedData>,
) {
    for blinded_data in table_data {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();

        let cell = html_row.insert_cell().unwrap();
        cell.set_text_content(Some(&blinded_data.handle.to_string()));

        let cell = html_row.insert_cell().unwrap();
        cell.set_text_content(Some(&blinded_data.data_value.to_string()));
    }
}

impl Display for FinalizedPseudonym {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NYM({}...)", hex::encode(&self.0[0..5]))
    }
}

impl Display for BlindedIdentifiableHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BLIND_ID({}..., {}...)",
            hex::encode(&self.0 .0.raw_bytes()[0..5]),
            hex::encode(&self.0 .1.raw_bytes()[0..5]),
        )
    }
}

impl Display for BlindedPseudonymizedHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BLIND_NYM({}..., {}...)",
            hex::encode(&self.0 .0.raw_bytes()[0..5]),
            hex::encode(&self.0 .1.raw_bytes()[0..5]),
        )
    }
}

impl Display for DataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8(self.value.clone()).unwrap())
    }
}

impl Display for EncryptedDataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ENC({}...)", hex::encode(&self.value[0..5]),)
    }
}
