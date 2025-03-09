use ocrs::{ImageSource, OcrEngine, OcrEngineParams};
use rten::Model;

use crate::http;

pub struct OcrExtractor {
    model_file_path: String,
    detection_model_url: String,
    detection_model_path: String,
    recognition_model_url: String,
    recognition_model_path: String,
}

impl OcrExtractor {
    pub fn new(model_file_path: String) -> Self {
        Self {
            detection_model_url: String::from(
                "https://ocrs-models.s3-accelerate.amazonaws.com/text-detection.rten",
            ),
            detection_model_path: format!("{model_file_path}/text-detection.rten"),
            recognition_model_url: String::from(
                "https://ocrs-models.s3-accelerate.amazonaws.com/text-recognition.rten",
            ),
            recognition_model_path: format!("{model_file_path}/text-recognition.rten"),
            model_file_path,
        }
    }

    pub fn download_models(&self) {
        std::fs::create_dir_all(&self.model_file_path).unwrap();

        if !std::path::Path::new(&self.detection_model_path).exists() {
            std::fs::write(
                &self.detection_model_path,
                http::get(&self.detection_model_url),
            )
            .unwrap();
        }

        if !std::path::Path::new(&self.recognition_model_path).exists() {
            std::fs::write(
                &self.recognition_model_path,
                http::get(&self.recognition_model_url),
            )
            .unwrap();
        }

        println!("models downloaded");
    }

    /// Extracts the text from an image via optical character recognition (OCR).
    pub fn extract_text_image(&self, data: &[u8]) -> String {
        println!("loading models");
        let detection_model = Model::load_file(&self.detection_model_path).unwrap();
        let recognition_model = Model::load_file(&self.recognition_model_path).unwrap();

        println!("creating engine");
        let engine = OcrEngine::new(OcrEngineParams {
            detection_model: Some(detection_model),
            recognition_model: Some(recognition_model),
            ..Default::default()
        })
        .unwrap();

        use image::ImageReader;
        use std::io::Cursor;

        println!("extracting text");
        let img = ImageReader::new(Cursor::new(data))
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap()
            .into_rgb8();

        let img_source = ImageSource::from_bytes(img.as_raw(), img.dimensions()).unwrap();

        let ocr_input = engine.prepare_input(img_source).unwrap();

        println!("detecting words");
        let word_rects = engine.detect_words(&ocr_input).unwrap();

        let line_rects = engine.find_text_lines(&ocr_input, &word_rects);

        let line_texts = engine.recognize_text(&ocr_input, &line_rects).unwrap();

        println!("text extracted");
        line_texts
            .iter()
            .flatten()
            // Filter likely spurious detections. With future model improvements
            // this should become unnecessary.
            .map(|l| l.to_string())
            // .filter(|l| l.len() > 1)
            .collect::<Vec<String>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_text_image() {
        let data = std::fs::read("./resources/images/image.jpg").unwrap();
        let extractor = OcrExtractor::new("./resources/models/".to_string());
        extractor.download_models();
        let result = extractor.extract_text_image(&data);

        assert_eq!(result, "https://github.com");
    }
}
