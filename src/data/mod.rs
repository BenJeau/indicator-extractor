mod pdf;
pub use pdf::PdfExtractor;

pub trait DataExtractor {
    fn extract(&self, data: &[u8]) -> String;
}
