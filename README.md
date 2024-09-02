# indicator-extractor

Extract indicators (IP, domain, email, hashes, Bitcoin addresses, Litecoin addresses, etc.) from a string or a PDF file written in Rust.

## Usage - Rust

[![Build status](https://github.com/BenJeau/indicator-extractor/actions/workflows/release.yaml/badge.svg?branch=main)](https://github.com/BenJeau/indicator-extractor/actions/workflows/release.yaml)
[![Crates.io Version](https://img.shields.io/crates/v/indicator-extractor)](https://crates.io/crates/indicator-extractor)
[![Documentation](https://docs.rs/indicator-extractor/badge.svg)](https://docs.rs/indicator-extractor)

The crate is available on [crates.io](https://crates.io/crates/indicator-extractor) and can be installed like the following:

```
cargo add indicator-extractor
```

### To extract indicators from a string/bytes

```rust
use indicator_extractor::parser::extract_indicators;

let result = extract_indicators("https://github.com".as_bytes());
println!("{:?}", result); // Ok(([], [Indicator::Url("https://github.com")])
```

### To extract indicators from a PDF file

```rust
use indicator_extractor::{data::{PdfExtractor, DataExtractor}, parser::extract_indicators};

let pdf_data = std::fs::read("./somewhere/pdf_file_path.pdf").unwrap();
let pdf_string = PdfExtractor.extract(&pdf_data);
let result = extract_indicators(pdf_string.as_bytes());
```

## Usage - Web

[![NPM Version](https://img.shields.io/npm/v/indicator-extractor)](https://www.npmjs.com/package/indicator-extractor)

A WebAssembly build is available on npm and can be installed like the following:

```bash
npm install indicator-extractor
```

Then you can use it like this:

```ts
import {
  extractIndicators,
  extractIndicatorsBytes,
  parsePdf,
  Indicator,
} from "indicator-extractor/indicator_extractor";

// Extract indicators from a string
const indicators: Indicator[] = extractIndicators("https://github.com");
console.log(indicators); // [{"kind":"url","value":"https://github.com"}]

// Or if you prefer bytes
const extractPdf: Indicator[] = extractIndicatorsBytes(new Uint8Array());

// You can also parse a PDF file to get its text
const pdfData: string = parsePdf(new Uint8Array());
// Where you can then use `extractIndicators` on the text
const pdfIndicators: Indicator[] = extractIndicators(pdfData);
```
