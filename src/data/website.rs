use crate::data::DataExtractor;

pub struct WebsiteExtractor;

impl DataExtractor for WebsiteExtractor {
    fn extract(&self, data: &[u8]) -> String {
        ureq::get(std::str::from_utf8(data).unwrap())
            .call()
            .unwrap()
            .into_string()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::extract_indicators;

    #[test]
    fn test_website_extract() {
        let extractor = WebsiteExtractor;
        let result = extractor.extract(&b"https://github.com".to_vec());

        let indicators = extract_indicators(&result.as_bytes()).unwrap();

        for indicator in indicators.1 {
            println!("{:?}", indicator);
        }

        assert!(false);
    }
}
