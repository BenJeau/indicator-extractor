//! Various data extractors to then parse indicators from.
//!
//! You will need to import the [`DataExtractor`] trait to use any of the data extractors.
//!
//! Currently the project only supports parsing of PDF files, but the goal is to add support for other file types and extraction methods thanks to the DataExtractor trait.

mod pdf;
pub use pdf::PdfExtractor;

/// Trait to extract data from a byte array.
pub trait DataExtractor {
    /// Extracts data from a byte array into a readable string with potential indicators.
    fn extract(&self, data: &[u8]) -> String;
}
