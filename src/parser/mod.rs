use helpers::{dec_u8, defanged_colon, defanged_period, hex_u16, is_not_digit, is_not_hex_digit};
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while},
    character::{
        complete::{alphanumeric1, hex_digit1, multispace0, multispace1},
        is_alphanumeric,
    },
    combinator::{complete, opt},
    error::{make_error, ErrorKind},
    multi::{many1, separated_list0, separated_list1},
    sequence::preceded,
    Err, IResult,
};
use std::net::{Ipv4Addr, Ipv6Addr};

mod helpers;

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
        preceded(opt(is_not(" \t\r\n")), multispace1),
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
    let (input, _) = opt(take_while(|c| {
        c != b'.' && c != b'-' && c != b'_' && c != b'+' && !is_alphanumeric(c)
    }))(input)?;

    let (input, email) =
        many1(alt((alphanumeric1, tag("."), tag("-"), tag("_"), tag("+"))))(input)?;
    let (input, _) = tag("@")(input)?;
    let (input, first_part) = many1(alt((alphanumeric1, tag("-"))))(input)?;
    let (input, domain) = preceded(defanged_period, many1(alt((alphanumeric1, tag("-")))))(input)?;

    Ok((
        input,
        Indicator::Email(format!(
            "{}@{}.{}",
            std::str::from_utf8(&email.concat()).unwrap(),
            std::str::from_utf8(&first_part.concat()).unwrap(),
            std::str::from_utf8(&domain.concat()).unwrap()
        )),
    ))
}

fn extract_ipv4(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(is_not_digit))(input)?;

    let (input, octects) = separated_list1(defanged_period, dec_u8)(input)?;

    if octects.len() != 4 {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }

    let ipv4_addr = Ipv4Addr::new(octects[0], octects[1], octects[2], octects[3]);

    Ok((input, Indicator::Ipv4(ipv4_addr)))
}

fn extract_ipv6(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| c != b':' && !is_alphanumeric(c)))(input)?;

    let (input, hexes) = separated_list1(defanged_colon, hex_u16)(input)?;

    if hexes.len() != 8 {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }

    let ipv6_addr = Ipv6Addr::new(
        hexes[0], hexes[1], hexes[2], hexes[3], hexes[4], hexes[5], hexes[6], hexes[7],
    );

    Ok((input, Indicator::Ipv6(ipv6_addr)))
}

fn extract_hash(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(is_not_hex_digit))(input)?;

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
    fn test_extract_single_ipv4_with_garbage() {
        let input = "asdf127.0.0.1";
        let expected = Indicator::Ipv4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

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
    fn test_extract_single_partially_defanged_ipv6() {
        let input = "2001:0db8[:]85a3[:]0000:0000[:]8a2e:0370:7334";
        let expected = Indicator::Ipv6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        ));

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
