//! A fast indicator extractor based on a paser combinator framework ([nom](https://github.com/rust-bakery/nom)) and a PDF parser ([pdf-extract](https://github.com/benjeffrey/pdf-extract)).
//!
//! The goal is to be able to extract indicators either defanged or not with `[.]`, `(.)`, `[:]`, or `(:)`. The exhaustive list of types can be found in the [`parser::Indicator`] enum. Here's an overview of the types
//! - IPv4
//! - IPv6
//! - Domains
//! - URLs
//! - Emails
//! - Hashes
//! - Filenames
//! - Bicoin addresses
//! - Litecoin addresses
//!
//! Currently the project only supports parsing of PDF files, but the goal is to add support for other file types and extraction methods thanks to the DataExtractor trait.
//!
//! The project is still in its early stages, so expect some breaking changes.
//!
//! An online playground is available at [ioc-extractor.jeaurond.dev](https://ioc-extractor.jeaurond.dev).
//!
//! # Usage
//!
//! To extract indicators from a string/bytes:
//!
//! ```
//! use indicator_extractor::parser::extract_indicators;
//!
//! let result = extract_indicators("https://github.com".as_bytes());
//! println!("{:?}", result); // Ok(([], [Indicator::Url("https://github.com")])
//! ```
//!
//! To extract indicators from a PDF file:
//!
//! ```
//! use indicator_extractor::{data::{PdfExtractor, DataExtractor}, parser::extract_indicators};
//!
//! let pdf_data = std::fs::read("./resources/pdfs/aa23-131a_malicious_actors_exploit_cve-2023-27350_in_papercut_mf_and_ng_1.pdf").unwrap();
//! let pdf_string = PdfExtractor.extract(&pdf_data);
//! let result = extract_indicators(pdf_string.as_bytes());
//! ```
//!
//! # WebAssembly
//!
//! The project is written in Rust and can be used in a WebAssembly build or as a Rust library. To use the WebAssembly build, you can install the package [indicator-extractor](https://www.npmjs.com/package/indicator-extractor) npm package.

pub mod data;
pub mod parser;

#[cfg(target_family = "wasm")]
mod wasm;

#[cfg(target_family = "wasm")]
pub use crate::wasm::*;
