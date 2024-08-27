#[cfg(feature = "pdf")]
mod pdf;

#[cfg(feature = "pdf")]
pub use pdf::PdfExtractor;

#[cfg(feature = "website")]
mod website;

#[cfg(feature = "website")]
pub use website::WebsiteExtractor;

trait DataExtractor {
    fn extract(&self, data: &[u8]) -> String;
}
