# indicator-extractor

Extract indicators (IP, domain, email, hashes, etc.) from a string or a PDF file written in Rust.

## Usage

### Web [![NPM Version](https://img.shields.io/npm/v/indicator-extractor?style=flat-square)](https://www.npmjs.com/package/indicator-extractor)

A WebAssembly build is available on npm and can be installed like the following:

```bash
npm install indicator-extractor
```

Then you can use it like this:

```js
import { extract_str, extract_pdf, extract_bytes } from "indicator-extractor";

const resultStr = extract_str("https://github.com");
console.log(resultStr); // ['{"kind":"Url","value":"https://github.com"}']

// Similarly for the other functions

const extractPdf = extract_pdf(new Uint8Array());
const extractBytes = extract_bytes(new Uint8Array());
```

### Rust [![Crates.io Version](https://img.shields.io/crates/v/indicator-extractor?style=flat-square)](https://crates.io/crates/indicator-extractor)

The crate is available on [crates.io](https://crates.io/crates/indicator-extractor) and can be installed like the following:

```
cargo add indicator-extractor
```

#### To extract indicators from a string/bytes

```rust
use indicator_extractor::parser::extract_indicators;

let result = extract_indicators("https://github.com".as_bytes());
println!("{:?}", result); // Ok(([], [Indicator::Url("https://github.com")])
```

#### To extract indicators from a PDF file

```rust
use indicator_extractor::{data{::PdfExtractor, DataExtractor}, parser::extract_indicators};

let pdf_data = std::fs::read("./somewhere/pdf_file_path.pdf").unwrap();
let pdf_string = PdfExtractor.extract(&pdf_data);
let result = extract_indicators(pdf_string.as_bytes());
```
