//! Various data extractors to then parse indicators from.
//!
//! Currently the project only supports parsing of PDF files and website scraping, but the goal is to add support for other file types and extraction methods thanks to the DataExtractor trait.

mod pdf;
mod website;

pub use pdf::extract_text_pdf;
pub use website::scrape_website;
