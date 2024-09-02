use bitcoin::{
    is_valid_bitcoin_p2pkh_address, is_valid_bitcoin_p2sh_address, is_valid_bitcoin_p2wpkh_address,
    is_valid_bitcoin_p2wsh_address, is_valid_litecoin_p2wpkh_address,
};
use helpers::{
    bytes_to_string, dec_u8, defanged_colon, defanged_period, hex_u16, is_base58, is_bech32,
    is_multispace, is_not_digit, is_not_hex_digit,
};
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, tag_no_case, take_till, take_while},
    character::{
        complete::{alphanumeric1, hex_digit1, multispace0, multispace1},
        is_alphanumeric,
    },
    combinator::{complete, opt},
    error::{make_error, ErrorKind},
    multi::{many1, separated_list0, separated_list1},
    sequence::preceded,
    Err, IResult, Parser,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::LazyLock,
};

mod bitcoin;
mod helpers;

static TLD_EXTRACTOR: LazyLock<tldextract::TldExtractor> =
    LazyLock::new(|| tldextract::TldExtractor::new(Default::default()));

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum Indicator {
    Url(String),
    Domain(String),
    File(String),
    Email(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Sha512(String),
    Sha256(String),
    Sha1(String),
    Md5(String),
    BitcoinP2pkhAddress(String),
    BitcoinP2shAddress(String),
    BitcoinP2wpkhAddress(String),
    BitcoinP2wshAddress(String),
    LitecoinP2pkhAddress(String),
    LitecoinP2wpkhAddress(String),
}

pub fn extract_indicators(input: &[u8]) -> IResult<&[u8], Vec<Indicator>> {
    let (input, _) = multispace0(input)?;
    let (input, indicator) = complete(separated_list0(
        opt(is_not(" \t\r\n")).and(multispace1),
        opt(extract_indicator),
    ))(input)?;

    let mut indicators = indicator.into_iter().flatten().collect::<Vec<Indicator>>();
    indicators.sort();
    indicators.dedup();

    Ok((input, indicators))
}

pub fn extract_indicator(input: &[u8]) -> IResult<&[u8], Indicator> {
    alt((
        extract_url,
        extract_email,
        extract_ipv4,
        extract_ipv6,
        extract_hash,
        extract_domain,
        extract_bitcoin_p2pkh_address,
        extract_bitcoin_p2sh_address,
        extract_bitcoin_p2wpkh_address,
        extract_bitcoin_p2wsh_address,
        extract_litecoin_p2wpkh_address,
    ))(input)
}

fn extract_url(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, scheme) = alt((tag_no_case("https"), tag_no_case("http")))(input)?;
    let (input, _) = defanged_colon(input)?;
    let (input, _) = tag("//")(input)?;
    let (input, host) = separated_list1(defanged_period, alt((alphanumeric1, tag("-"))))(input)?;
    let (input, rest) = take_till(is_multispace)(input)?;

    Ok((
        input,
        Indicator::Url(format!(
            "{}://{}{}",
            std::str::from_utf8(scheme).unwrap(),
            host.into_iter()
                .map(|s| std::str::from_utf8(s).unwrap())
                .collect::<Vec<&str>>()
                .join("."),
            std::str::from_utf8(rest).unwrap()
        )),
    ))
}

fn extract_domain(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, data) = separated_list1(defanged_period, alt((alphanumeric1, tag("-"))))(input)?;

    if data.len() < 2 {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }

    let potential_domain = data
        .into_iter()
        .map(|s| std::str::from_utf8(s).unwrap())
        .collect::<Vec<&str>>()
        .join(".");

    let Ok(tld) = TLD_EXTRACTOR.extract(&potential_domain) else {
        return Ok((input, Indicator::File(potential_domain)));
    };

    if tld.domain.is_some() && tld.suffix.is_some() {
        return Ok((
            input,
            Indicator::Domain(format!(
                "{}{}.{}",
                if let Some(subdomain) = tld.subdomain.as_ref() {
                    format!("{}.", subdomain)
                } else {
                    "".to_string()
                },
                tld.domain.unwrap(),
                tld.suffix.unwrap()
            )),
        ));
    }

    Ok((input, Indicator::File(potential_domain)))
}

fn extract_email(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| {
        c != b'.' && c != b'-' && c != b'_' && c != b'+' && !is_alphanumeric(c) && !is_multispace(c)
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
    let (input, _) = opt(take_while(|c| is_not_digit(c) && !is_multispace(c)))(input)?;

    let (input, octects) = separated_list1(defanged_period, dec_u8)(input)?;
    if octects.len() != 4 {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }

    let ipv4_addr = Ipv4Addr::new(octects[0], octects[1], octects[2], octects[3]);
    Ok((input, Indicator::Ipv4(ipv4_addr)))
}

fn extract_ipv6(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| {
        c != b':' && !is_alphanumeric(c) && !is_multispace(c)
    }))(input)?;

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
    let (input, _) = opt(take_while(|c| is_not_hex_digit(c) && !is_multispace(c)))(input)?;

    let (input, hash) = hex_digit1(input)?;

    match hash.len() {
        32 => Ok((input, Indicator::Md5(bytes_to_string(hash)))),
        40 => Ok((input, Indicator::Sha1(bytes_to_string(hash)))),
        64 => Ok((input, Indicator::Sha256(bytes_to_string(hash)))),
        128 => Ok((input, Indicator::Sha512(bytes_to_string(hash)))),
        _ => Err(Err::Error(make_error(input, ErrorKind::Verify))),
    }
}

fn extract_bitcoin_p2pkh_address(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| c != b'1' && !is_multispace(c)))(input)?;

    let (input, prefix) = tag("1")(input)?;
    let (input, address) = is_base58(input)?;

    if is_valid_bitcoin_p2pkh_address(address) {
        Ok((
            input,
            Indicator::BitcoinP2pkhAddress(bytes_to_string(&[prefix, address].concat())),
        ))
    } else {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }
}

fn extract_bitcoin_p2sh_address(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| c != b'3' && !is_multispace(c)))(input)?;

    let (input, prefix) = tag("3")(input)?;
    let (input, address) = is_base58(input)?;

    if is_valid_bitcoin_p2sh_address(address) {
        Ok((
            input,
            Indicator::BitcoinP2shAddress(bytes_to_string(&[prefix, address].concat())),
        ))
    } else {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }
}

fn extract_bitcoin_p2wpkh_address(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| c != b'b' && c != b't' && !is_multispace(c)))(input)?;

    let (input, prefix) = alt((tag_no_case("bc1"), tag_no_case("tb1")))(input)?;
    let (input, address) = is_bech32(input)?;

    let address = &[prefix, address].concat();

    if is_valid_bitcoin_p2wpkh_address(address) {
        Ok((
            input,
            Indicator::BitcoinP2wpkhAddress(bytes_to_string(address)),
        ))
    } else {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }
}

fn extract_bitcoin_p2wsh_address(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| c != b'b' && c != b't' && !is_multispace(c)))(input)?;

    let (input, prefix) = alt((tag_no_case("bc1"), tag_no_case("tb1")))(input)?;
    let (input, address) = is_bech32(input)?;

    let address = &[prefix, address].concat();

    if is_valid_bitcoin_p2wsh_address(address) {
        Ok((
            input,
            Indicator::BitcoinP2wshAddress(bytes_to_string(address)),
        ))
    } else {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }
}

fn extract_litecoin_p2wpkh_address(input: &[u8]) -> IResult<&[u8], Indicator> {
    let (input, _) = opt(take_while(|c| c != b'l' && !is_multispace(c)))(input)?;

    let (input, prefix) = tag("ltc1")(input)?;
    let (input, address) = is_bech32(input)?;

    let address = &[prefix, address].concat();

    if is_valid_litecoin_p2wpkh_address(address) {
        Ok((
            input,
            Indicator::LitecoinP2wpkhAddress(bytes_to_string(address)),
        ))
    } else {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_single_litecoin_p2wpkh_address() {
        let input = "ltc1q8c6fshw2dlwun7ekn9qwf37cu2rn755u9ym7p0";
        let expected = Indicator::LitecoinP2wpkhAddress(
            "ltc1q8c6fshw2dlwun7ekn9qwf37cu2rn755u9ym7p0".to_string(),
        );

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_bitcoin_pubkey() {
        let input = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let expected =
            Indicator::BitcoinP2pkhAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_url() {
        let input = "http://www.example.com/foo/bar";
        let expected = Indicator::Url("http://www.example.com/foo/bar".to_string());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

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
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        )];

        assert_eq!(
            extract_indicators(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_md5() {
        let input = "d41d8cd98f00b204e9800998ecf8427e";
        let expected = Indicator::Md5("d41d8cd98f00b204e9800998ecf8427e".to_string());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_sha1() {
        let input = "SHA1 hash: da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let expected = vec![Indicator::Sha1(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
        )];

        assert_eq!(
            extract_indicators(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_sha1() {
        let input = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let expected = Indicator::Sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_sha256() {
        let input = "SHA256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let expected = vec![Indicator::Sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
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
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
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
            "f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc".to_string()
        )];

        assert_eq!(
            extract_indicators(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_extract_single_sha512() {
        let input = "f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc";
        let expected = Indicator::Sha512("f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc".to_string());

        assert_eq!(
            extract_indicator(input.as_bytes()),
            Ok(("".as_bytes(), expected))
        );
    }

    #[test]
    fn test_multiple_indicators() {
        let input = r#"    Domain: AM6P194CA0000.outlook.office.com
    Domain: AMS0EPF000000A0.eurprd01.prod.outlook.com
    Domain: me512.com
    File: 1.0
    File: 15.21.7897.01
    File: 15.26.7918.123
    File: AA6P194CA0000.EURP001.PROD.OUTLOOK.COM
    File: CC3PR84AB3445.LAPE210.PROD.OUTLOOK.COM
    Email: 8ab3fa386978525c7fd59cb135f0fbc598c8@outlook.com
    Email: ALLOW@OUTLOOK.COM
    Email: allow@outlook.com
    Ipv4: 10.167.20.233
    Ipv4: 96.21.95.53
    BitcoinP2pkhAddress: 15N6Q12yFN3xa8ChqXDWWGgZPYcZdoTyRa
    LitecoinP2wpkhAddress: ltc1q8c6fshw2dlwun7ekn9qwf37cu2rn755u9ym7p0"#;

        let expected = vec![
            Indicator::Domain("AM6P194CA0000.outlook.office.com".to_string()),
            Indicator::Domain("AMS0EPF000000A0.eurprd01.prod.outlook.com".to_string()),
            Indicator::Domain("me512.com".to_string()),
            Indicator::File("1.0".to_string()),
            Indicator::File("15.21.7897.01".to_string()),
            Indicator::File("15.26.7918.123".to_string()),
            Indicator::File("AA6P194CA0000.EURP001.PROD.OUTLOOK.COM".to_string()),
            Indicator::File("CC3PR84AB3445.LAPE210.PROD.OUTLOOK.COM".to_string()),
            Indicator::Email("8ab3fa386978525c7fd59cb135f0fbc598c8@outlook.com".to_string()),
            Indicator::Email("ALLOW@OUTLOOK.COM".to_string()),
            Indicator::Email("allow@outlook.com".to_string()),
            Indicator::Ipv4(Ipv4Addr::new(10, 167, 20, 233)),
            Indicator::Ipv4(Ipv4Addr::new(96, 21, 95, 53)),
            Indicator::BitcoinP2pkhAddress("15N6Q12yFN3xa8ChqXDWWGgZPYcZdoTyRa".to_string()),
            Indicator::LitecoinP2wpkhAddress(
                "ltc1q8c6fshw2dlwun7ekn9qwf37cu2rn755u9ym7p0".to_string(),
            ),
        ];

        let (input, result) = extract_indicators(input.as_bytes()).unwrap();

        for indicator in expected.iter() {
            assert!(
                result.contains(indicator),
                "indicator {indicator:?} doesn't match"
            );
        }

        assert_eq!(input.len(), 0);
    }
}
