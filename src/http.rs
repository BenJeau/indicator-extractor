#[cfg(not(target_arch = "wasm32"))]
pub async fn get(url: &str) -> Vec<u8> {
    use std::io::Read;
    let resp = ureq::get(url).call().unwrap();

    let len: usize = resp
        .header("Content-Length")
        .unwrap_or("10")
        .parse()
        .unwrap();

    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    resp.into_reader()
        .take(10_000_000)
        .read_to_end(&mut bytes)
        .unwrap();

    bytes
}

#[cfg(target_arch = "wasm32")]
pub async fn get(url: &str) -> Vec<u8> {
    use js_sys::{ArrayBuffer, Uint8Array};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Blob, Request, RequestInit, RequestMode, Response};

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(url, &opts).unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let blob = JsFuture::from(resp.blob().unwrap()).await.unwrap();
    let blob: Blob = blob.dyn_into::<Blob>().unwrap();
    let array_buffer = JsFuture::from(blob.array_buffer()).await.unwrap();
    let array_buffer: ArrayBuffer = array_buffer.dyn_into().unwrap();
    let uint8_array = Uint8Array::new(&array_buffer);

    uint8_array.to_vec()
}
