use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while},
    character::{
        complete::{hex_digit1, multispace0},
        is_digit,
        streaming::multispace1,
    },
    combinator::{complete, opt},
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

pub fn extract_indicators(input: &[u8]) -> IResult<&[u8], Vec<Indicator>> {
    let (input, _) = multispace0(input)?;
    let (input, indicator) = complete(separated_list0(
        preceded(is_not(" \t\r\n"), multispace1),
        opt(extract_indicator),
    ))(input)?;
    Ok((input, indicator.into_iter().flatten().collect()))
}

pub fn extract_indicator(input: &[u8]) -> IResult<&[u8], Indicator> {
    alt((
        extract_url,
        extract_email,
        extract_ipv4,
        extract_ipv6,
        extract_hash,
    ))(input)
}

fn extract_url(input: &[u8]) -> IResult<&[u8], Indicator> {
    Err(Err::Error(make_error(input, ErrorKind::Verify)))
}

fn extract_email(input: &[u8]) -> IResult<&[u8], Indicator> {
    Err(Err::Error(make_error(input, ErrorKind::Verify)))
}

fn extract_ipv4(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, first_octet) = octect(input)?;
    let (input, _) = eat_defanged_period(input)?;
    let (input, second_octet) = octect(input)?;
    let (input, _) = eat_defanged_period(input)?;
    let (input, third_octet) = octect(input)?;
    let (input, _) = eat_defanged_period(input)?;
    let (input, fourth_octet) = octect(input)?;

    let ipv4_addr = Ipv4Addr::new(first_octet, second_octet, third_octet, fourth_octet);

    Ok((input, Indicator::Ipv4(ipv4_addr)))
}

fn octect(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, octet_parts) = take_while(is_digit)(input)?;
    Ok((
        input,
        octet_parts
            .iter()
            .rev()
            .enumerate()
            .fold(0, |acc, (i, c)| acc + 10_u8.pow(i as u32) * (c - b'0')),
    ))
}

fn eat_defanged_period(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((tag("."), tag("[.]")))(input)
}

fn extract_ipv6(input: &[u8]) -> IResult<&[u8], Indicator> {
    Err(Err::Error(make_error(input, ErrorKind::Verify)))
}

fn extract_hash(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, hash) = hex_digit1(input)?;

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
    fn test_extract_single_ipv4() {
        let input = "127.0.0.1";
        let expected = Indicator::Ipv4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_partially_defanged_ipv4() {
        let input = "127[.]0.0[.]1";
        let expected = Indicator::Ipv4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_fully_defanged_ipv4() {
        let input = "127[.]0[.]0[.]1";
        let expected = Indicator::Ipv4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

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
