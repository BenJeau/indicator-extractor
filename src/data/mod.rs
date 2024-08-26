mod pdf;

pub use pdf::PdfExtractor;

trait DataExtractor {
    fn extract(&self, data: &[u8]) -> String;
}
