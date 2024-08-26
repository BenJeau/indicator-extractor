use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    branch::alt,
    bytes::complete::take,
    combinator::opt,
    error::{make_error, ErrorKind},
    Err, IResult,
};

#[derive(Debug, PartialEq)]
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
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }

    fn extract_email(input: &str) -> IResult<&str, Self> {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }

    fn extract_ipv4(input: &str) -> IResult<&str, Self> {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }

    fn extract_ipv6(input: &str) -> IResult<&str, Self> {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_md5() {
        let input = "MD5 hash: d41d8cd98f00b204e9800998ecf8427e";
        let expected = vec![Indicator::Md5(
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        )];

        assert_eq!(Indicator::extract_indicators(input), expected);
    }

    #[test]
    fn test_extract_sha1() {
        let input = "SHA1 hash: da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let expected = vec![Indicator::Sha1(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
        )];

        assert_eq!(Indicator::extract_indicators(input), expected);
    }

    #[test]
    fn test_extract_sha256() {
        let input = "SHA256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let expected = vec![Indicator::Sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        )];

        assert_eq!(Indicator::extract_indicators(input), expected);
    }

    #[test]
    fn test_extract_sha512() {
        let input = "SHA512 hash: f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc";
        let expected = vec![Indicator::Sha512(
            "f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc".to_string(),
        )];

        assert_eq!(Indicator::extract_indicators(input), expected);
    }
}
