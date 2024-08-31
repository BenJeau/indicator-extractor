use nom::{
    branch::alt,
    bytes::complete::tag,
    character::{complete::digit1, is_digit, is_hex_digit},
    error::{make_error, ErrorKind},
    number::complete::hex_u32,
    Err, IResult,
};

pub(crate) fn hex_u16(input: &[u8]) -> IResult<&[u8], u16> {
    let (input, data) = hex_u32(input)?;
    Ok((input, data as u16))
}

pub(crate) fn dec_u8(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, data) = digit1(input)?;
    let octect_string =
        std::str::from_utf8(data).map_err(|_| Err::Error(make_error(input, ErrorKind::Verify)))?;
    Ok((
        input,
        octect_string
            .parse()
            .map_err(|_| Err::Error(make_error(input, ErrorKind::Verify)))?,
    ))
}

pub(crate) fn defanged_period(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((tag("."), tag("[.]"), tag("(.)")))(input)
}

pub(crate) fn defanged_colon(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((tag(":"), tag("[:]"), tag("(:)")))(input)
}

pub(crate) fn is_not_digit(c: u8) -> bool {
    !is_digit(c)
}

pub(crate) fn is_not_hex_digit(c: u8) -> bool {
    !is_hex_digit(c)
}

pub(crate) fn is_multispace(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\r' || c == b'\n'
}

pub(crate) fn bytes_to_string(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes).unwrap().to_string()
}
