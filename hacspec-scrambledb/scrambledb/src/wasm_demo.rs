use hacspec_lib::Randomness;
use p256::{NatMod, P256FieldElement};
use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;
use web_sys::{Document, Element, HtmlTableElement};

use crate::table::MultiColumnTable;
use crate::table::SingleColumnTable;
use crate::{
    setup::{ConverterContext, StoreContext},
    table::{BlindTable, Column, ConvertedTable, PlainTable, PseudonymizedTable},
};

#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
fn run() -> Result<(), JsValue> {
    use rand::prelude::*;
    use web_sys::console;
    let mut rng = rand::thread_rng();
    let mut randomness = [0u8; 1000000];
    rng.fill_bytes(&mut randomness);
    let mut randomness = Randomness::new(randomness.to_vec());

    let converter_context = ConverterContext::setup(&mut randomness).unwrap();
    let lake_context = StoreContext::setup(&mut randomness).unwrap();

    // == Generate Plain Table ==
    let plain_table = generate_plain_table();

    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");

    let plain_table_element =
        prep_multicol_table_html_to_dom_id(&"data-source-table-plain", &plain_table, &document);
    fill_plain_table_element(&plain_table_element, &plain_table);

    let (lake_ek, lake_bpk) = lake_context.public_keys();

    // == Blind Table for Pseudonymization ==
    let blind_table =
        crate::split::prepare_split_conversion(lake_ek, lake_bpk, plain_table, &mut randomness)
            .unwrap();

    let blind_table_element =
        prep_multicol_table_html_to_dom_id(&"data-source-table-blind", &blind_table, &document);
    //fill_blind_table_element(&blind_table_element, &blind_table);

    // // == Blind Pseudonymized Table ==
    let converted_tables = crate::split::split_conversion(
        &converter_context,
        lake_bpk,
        lake_ek,
        blind_table,
        &mut randomness,
    )
    .unwrap();

    // == Unblinded Pseudonymized Table ==
    let lake_tables =
        crate::finalize::finalize_conversion(&lake_context, converted_tables).unwrap();

    for lake_table in lake_tables.iter() {
        let lake_table_element =
            add_column_html_to_dom_id(&"data-lake-tables", &lake_table, &document);
        //fill_pseudonymized_table_element(&lake_table_element, lake_table);
    }

    let processor_context = StoreContext::setup(&mut randomness).unwrap();

    let (bpk_processor, ek_processor) = processor_context.public_keys();
    let blind_tables = crate::join::prepare_join_conversion(
        &lake_context,
        bpk_processor,
        ek_processor,
        lake_tables,
        &mut randomness,
    )
    .unwrap();

    let converted_join_tables = crate::join::join_conversion(
        &converter_context,
        bpk_processor,
        ek_processor,
        blind_tables,
        &mut randomness,
    )
    .unwrap();

    let joined_tables =
        crate::finalize::finalize_conversion(&lake_context, converted_join_tables).unwrap();

    for lake_table in joined_tables.iter() {
        let lake_table_element =
            add_column_html_to_dom_id(&"data-processor-joined", &lake_table, &document);
        //fill_pseudonymized_table_element(&lake_table_element, lake_table);
    }
    console::log_1(&"Okay...".into());

    Ok(())
}

fn fill_pseudonymized_table_element(table_element: &HtmlTableElement, table: &PseudonymizedTable) {
    todo!()
}

fn add_column_html_to_dom_id(
    element_id: &str,
    table: &PseudonymizedTable,
    document: &Document,
) -> HtmlTableElement {
    // Create table and add it to given dom element (should be a <div>)

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

    // insert a dummy cell in the header for correct alignment of attribute header
    let _dummy_cell = header_row.insert_cell().unwrap();
    let header_cell = header_row.insert_cell().unwrap();
    header_cell.set_text_content(Some(&table.column().attribute()));

    t_head.append_child(&header_row).unwrap();

    let t_caption = table_element.create_caption();

    t_caption.set_text_content(Some(&table.identifier()));

    table_div.append_child(&table_element).unwrap();
    table_element
}

fn prep_multicol_table_html_to_dom_id<K, V>(
    element_id: &str,
    table: &MultiColumnTable<K, V>,
    document: &Document,
) -> HtmlTableElement
where
    K: Clone,
    V: Clone,
{
    let table_element: HtmlTableElement = document
        .get_element_by_id(element_id)
        .expect("Document should have plain table element.")
        .dyn_into::<web_sys::HtmlTableElement>()
        .unwrap();

    let t_head = table_element.create_t_head();

    let header_row = document
        .create_element("tr")
        .unwrap()
        .dyn_into::<web_sys::HtmlTableRowElement>()
        .unwrap();

    // insert a dummy cell in the header for correct alignment of attribute headers
    let _dummy_cell = header_row.insert_cell().unwrap();

    for colum in table.columns() {
        let header_cell = header_row.insert_cell().unwrap();
        header_cell.set_text_content(Some(&colum.attribute()));
    }

    t_head.append_child(&header_row).unwrap();

    let t_caption = table_element.create_caption();

    t_caption.set_text_content(Some(&table.identifier()));

    table_element
}

fn fill_plain_table_element(table_element: &HtmlTableElement, plain_table: &PlainTable) {
    for row in plain_table.rows() {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();
        let key_cell = html_row.insert_cell().unwrap();
        key_cell.set_text_content(Some(&row.0));
        for value in row.1 {
            let val_cell = html_row.insert_cell().unwrap();
            val_cell.set_text_content(Some(&hex::encode(value.raw_bytes())))
        }
    }
}

fn fill_blind_table_element(table_element: &HtmlTableElement, plain_table: &BlindTable) {
    for row in plain_table.rows() {
        let html_row = table_element
            .insert_row()
            .unwrap()
            .dyn_into::<web_sys::HtmlTableRowElement>()
            .unwrap();
        let key_cell = html_row.insert_cell().unwrap();
        let key_string = format!(
            "G({}), G({})",
            hex::encode(row.0 .0.raw_bytes()),
            hex::encode(row.0 .1.raw_bytes())
        );
        key_cell.set_text_content(Some(&key_string));
        for value in row.1 {
            let val_cell = html_row.insert_cell().unwrap();
            let val_string = format!(
                "G({}), G({})",
                hex::encode(value.0.raw_bytes()),
                hex::encode(value.1.raw_bytes())
            );
            val_cell.set_text_content(Some(&val_string))
        }
    }
}

fn generate_plain_table() -> PlainTable {
    let mut columns = Vec::new();
    columns.push(Column::new(
        String::from("SampleAttribute1"),
        vec![
            (
                String::from("A"),
                hash_to_curve::p256_hash::hash_to_curve(b"TestData1", b"sample_dst").unwrap(),
            ),
            (
                String::from("B"),
                hash_to_curve::p256_hash::hash_to_curve(b"TestData2", b"sample_dst").unwrap(),
            ),
        ],
    ));

    columns.push(Column::new(
        String::from("SampleAttribute2"),
        vec![
            (
                String::from("A"),
                hash_to_curve::p256_hash::hash_to_curve(b"TestData3", b"sample_dst").unwrap(),
            ),
            (
                String::from("B"),
                hash_to_curve::p256_hash::hash_to_curve(b"TestData4", b"sample_dst").unwrap(),
            ),
        ],
    ));

    columns.push(Column::new(
        String::from("SampleAttribute3"),
        vec![
            (
                String::from("A"),
                hash_to_curve::p256_hash::hash_to_curve(b"TestData5", b"sample_dst").unwrap(),
            ),
            (
                String::from("B"),
                hash_to_curve::p256_hash::hash_to_curve(b"TestData6", b"sample_dst").unwrap(),
            ),
        ],
    ));

    PlainTable::new(String::from("SampleTable"), columns)
}
