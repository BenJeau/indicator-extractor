use wasm_bindgen::prelude::wasm_bindgen;

pub mod data;
pub mod parser;

#[wasm_bindgen]
pub fn extract_bytes(input: &[u8]) -> Vec<String> {
    console_error_panic_hook::set_once();

    crate::parser::extract_indicators(input)
        .unwrap()
        .1
        .into_iter()
        .map(|i| serde_json::to_string(&i).unwrap())
        .collect()
}

#[wasm_bindgen]
pub fn extract_str(input: &str) -> Vec<String> {
    console_error_panic_hook::set_once();

    crate::parser::extract_indicators(input.as_bytes())
        .unwrap()
        .1
        .into_iter()
        .map(|i| serde_json::to_string(&i).unwrap())
        .collect()
}

#[wasm_bindgen]
pub fn extract_pdf(input: &[u8]) -> Vec<String> {
    console_error_panic_hook::set_once();

    use crate::data::DataExtractor;

    crate::parser::extract_indicators(crate::data::PdfExtractor.extract(input).as_bytes())
        .unwrap()
        .1
        .into_iter()
        .map(|i| serde_json::to_string(&i).unwrap())
        .collect()
}
