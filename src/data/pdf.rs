use crate::data::DataExtractor;

/// Extracts the text from a PDF file.
pub struct PdfExtractor;

impl DataExtractor for PdfExtractor {
    fn extract(&self, data: &[u8]) -> String {
        pdf_extract::extract_text_from_mem(data).unwrap()
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::parser::extract_indicators;

//     #[test]
//     fn test_extract() {
//         let path = std::path::Path::new("resources/pdfs/aa23-131a_malicious_actors_exploit_cve-2023-27350_in_papercut_mf_and_ng_1.pdf");
//         let data = std::fs::read(path).unwrap();
//         let extractor = PdfExtractor;
//         let result = extractor.extract(&data);

//         let indicators = extract_indicators(&result.as_bytes()).unwrap();

//         for indicator in indicators.1 {
//             println!("{:?}", indicator);
//         }

//         assert!(false);
//     }
// }
