use crate::data::{DataExtractor, PdfExtractor};
use wasm_bindgen::prelude::*;

pub mod data;
pub mod parser;

/// Extract indicators (IP, domain, email, hashes, Bicoin addresses, Litecoin addresses, etc.) from an array of bytes.
#[wasm_bindgen(js_name = extractIndicatorsBytes, skip_typescript)]
pub fn extract_indicators_bytes(input: &[u8]) -> JsValue {
    console_error_panic_hook::set_once();

    let data = crate::parser::extract_indicators(input).unwrap().1;

    serde_wasm_bindgen::to_value(&data).unwrap()
}

/// Extract indicators (IP, domain, email, hashes, Bicoin addresses, Litecoin addresses, etc.) from a string, uses `extractIndicatorsBytes` internally.
#[wasm_bindgen(js_name = extractIndicators, skip_typescript)]
pub fn extract_indicators_str(input: &str) -> JsValue {
    extract_indicators_bytes(input.as_bytes())
}

/// Extracts the text from a PDF file.
#[wasm_bindgen(js_name = parsePdf)]
pub fn parse_pdf(input: &[u8]) -> String {
    console_error_panic_hook::set_once();

    PdfExtractor.extract(input)
}

#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = include_str!("indicator_extractor.d.ts");
