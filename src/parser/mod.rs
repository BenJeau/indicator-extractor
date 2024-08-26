use std::net::{Ipv4Addr, Ipv6Addr};

enum Indicator {
    Url(String),
    Email(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Sha512(String),
    Sha256(String),
    Sha1(String),
    Md5(String),
}

impl Indicator {
    pub fn extract_indicators(input: &str) -> Vec<Self> {
        let mut output = vec![];
        todo!("parsing logic");
        return output;
    }
}
