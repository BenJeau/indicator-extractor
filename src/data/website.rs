use crate::http;

pub async fn scrape_website(url: &str) -> String {
    std::str::from_utf8(&http::get(url).await)
        .unwrap()
        .to_string()
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::parser::extract_indicators;

//     #[test]
//     fn test_website_extract() {
//         let result = extract(&b"https://github.com".to_vec());

//         let (_, indicators) = extract_indicators(&result.as_bytes()).unwrap();
//         assert!(indicators.len() > 0);
//     }
// }
