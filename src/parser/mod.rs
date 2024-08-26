use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    branch::alt,
    bytes::complete::take,
    combinator::opt,
    error::{make_error, ErrorKind},
    Err, IResult,
};

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
        input
            .split_whitespace()
            .flat_map(Self::extract_indicator)
            .filter_map(|(_, indicator)| indicator)
            .collect()
    }

    pub fn extract_indicator(input: &str) -> IResult<&str, Option<Self>> {
        opt(alt((
            Self::extract_url,
            Self::extract_email,
            Self::extract_ipv4,
            Self::extract_ipv6,
            Self::extract_sha512,
            Self::extract_sha256,
            Self::extract_sha1,
            Self::extract_md5,
        )))(input)
    }

    fn extract_url(input: &str) -> IResult<&str, Self> {
        todo!()
    }

    fn extract_email(input: &str) -> IResult<&str, Self> {
        todo!()
    }

    fn extract_ipv4(input: &str) -> IResult<&str, Self> {
        todo!()
    }

    fn extract_ipv6(input: &str) -> IResult<&str, Self> {
        todo!()
    }

    fn extract_sha512(input: &str) -> IResult<&str, Self> {
        let (input, sha512) = take(128usize)(input)?;

        if Self::all_hex(sha512) {
            Ok((input, Self::Sha512(sha512.to_lowercase())))
        } else {
            Err(Err::Error(make_error(input, ErrorKind::Verify)))
        }
    }

    fn extract_sha256(input: &str) -> IResult<&str, Self> {
        let (input, sha256) = take(64usize)(input)?;

        if Self::all_hex(sha256) {
            Ok((input, Self::Sha256(sha256.to_lowercase())))
        } else {
            Err(Err::Error(make_error(input, ErrorKind::Verify)))
        }
    }

    fn extract_sha1(input: &str) -> IResult<&str, Self> {
        let (input, sha1) = take(40usize)(input)?;

        if Self::all_hex(sha1) {
            Ok((input, Self::Sha1(sha1.to_lowercase())))
        } else {
            Err(Err::Error(make_error(input, ErrorKind::Verify)))
        }
    }

    fn extract_md5(input: &str) -> IResult<&str, Self> {
        let (input, md5) = take(32usize)(input)?;

        if Self::all_hex(md5) {
            Ok((input, Self::Md5(md5.to_lowercase())))
        } else {
            Err(Err::Error(make_error(input, ErrorKind::Verify)))
        }
    }

    fn all_hex(input: &str) -> bool {
        input.chars().all(|c| c.is_ascii_hexdigit())
    }
}
