use crate::data::{extract_text_pdf, scrape_website};
use wasm_bindgen::prelude::*;

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

    extract_text_pdf(input)
}

/// Scrapes a website and returns the text.
///
/// Might not work on all (most) websites due to CORS.
#[wasm_bindgen(js_name = scrapeWebstie)]
pub async fn scrape_website_ah(url: &str) -> String {
    console_error_panic_hook::set_once();

    scrape_website(url).await
}

#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = include_str!("indicator_extractor.d.ts");
