use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    branch::alt,
    bytes::complete::{is_not, take_while},
    character::{complete::multispace0, is_alphanumeric, streaming::multispace1},
    combinator::opt,
    error::{make_error, ErrorKind},
    multi::separated_list0,
    sequence::preceded,
    Err, IResult,
};

#[derive(Debug, PartialEq)]
pub enum Indicator<'a> {
    Url(String),
    Email(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Sha512(&'a [u8]),
    Sha256(&'a [u8]),
    Sha1(&'a [u8]),
    Md5(&'a [u8]),
}

pub fn extract_indicators<'a>(input: &'a [u8]) -> IResult<&'a [u8], Vec<Indicator>> {
    let (input, _) = multispace0(input)?;
    let (input, indicator) = separated_list0(
        preceded(is_not(" \t\r\n"), multispace1),
        opt(extract_indicator),
    )(input)?;
    Ok((input, indicator.into_iter().flatten().collect()))
}

pub fn extract_indicator<'a>(input: &'a [u8]) -> IResult<&'a [u8], Indicator> {
    alt((
        extract_url,
        extract_email,
        extract_ipv4,
        extract_ipv6,
        extract_hash,
    ))(input)
}

fn extract_url<'a>(input: &'a [u8]) -> IResult<&'a [u8], Indicator> {
    Err(Err::Error(make_error(input, ErrorKind::Verify)))
}

fn extract_email<'a>(input: &'a [u8]) -> IResult<&'a [u8], Indicator> {
    Err(Err::Error(make_error(input, ErrorKind::Verify)))
}

fn extract_ipv4<'a>(input: &'a [u8]) -> IResult<&'a [u8], Indicator> {
    Err(Err::Error(make_error(input, ErrorKind::Verify)))
}

fn extract_ipv6<'a>(input: &'a [u8]) -> IResult<&'a [u8], Indicator> {
    Err(Err::Error(make_error(input, ErrorKind::Verify)))
}

fn extract_hash<'a>(input: &'a [u8]) -> IResult<&'a [u8], Indicator> {
    let (input, hash) = take_while(is_alphanumeric)(input)?;

    match hash.len() {
        32 => Ok((input, Indicator::Md5(hash))),
        40 => Ok((input, Indicator::Sha1(hash))),
        64 => Ok((input, Indicator::Sha256(hash))),
        128 => Ok((input, Indicator::Sha512(hash))),
        _ => Err(Err::Error(make_error(input, ErrorKind::Verify))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_md5() {
        let input = "MD5 hash: d41d8cd98f00b204e9800998ecf8427e";
        let expected = vec![Indicator::Md5(
            "d41d8cd98f00b204e9800998ecf8427e".as_bytes(),
        )];

        assert_eq!(
            extract_indicators(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_md5() {
        let input = "d41d8cd98f00b204e9800998ecf8427e";
        let expected = Indicator::Md5("d41d8cd98f00b204e9800998ecf8427e".as_bytes());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_sha1() {
        let input = "SHA1 hash: da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let expected = vec![Indicator::Sha1(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".as_bytes(),
        )];

        assert_eq!(
            extract_indicators(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_sha1() {
        let input = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let expected = Indicator::Sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709".as_bytes());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_sha256() {
        let input = "SHA256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let expected = vec![Indicator::Sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".as_bytes(),
        )];

        assert_eq!(
            extract_indicators(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_sha256() {
        let input = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let expected = Indicator::Sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".as_bytes(),
        );

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_sha512() {
        let input = "SHA512 hash: f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc";
        let expected = vec![Indicator::Sha512(
            "f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc".as_bytes(),
        )];

        assert_eq!(
            extract_indicators(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_sha512() {
        let input = "f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc";
        let expected = Indicator::Sha512("f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc".as_bytes());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }
}
