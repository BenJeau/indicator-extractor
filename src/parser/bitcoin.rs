use bech32::Hrp;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

static BC_HRP: LazyLock<Hrp> = LazyLock::new(|| Hrp::parse("bc").unwrap());
static TB_HRP: LazyLock<Hrp> = LazyLock::new(|| Hrp::parse("tb").unwrap());
static LTC_HRP: LazyLock<Hrp> = LazyLock::new(|| Hrp::parse("ltc").unwrap());

pub(crate) fn is_valid_bitcoin_p2pkh_address(input: &[u8]) -> bool {
    if !(25..=34).contains(&input.len()) {
        return false;
    }

    let decoded_input = bs58::decode(input).into_vec().unwrap();

    let Some((data, checksum)) = decoded_input.split_at_checked(decoded_input.len() - 4) else {
        return false;
    };

    let mut sha256 = Sha256::new();
    sha256.update([0x00]);
    sha256.update(data);
    let hash = sha256.finalize();

    let mut pass2 = Sha256::new();
    pass2.update(hash);
    let hash2 = pass2.finalize();

    hash2.to_vec().starts_with(checksum)
}

pub(crate) fn is_valid_bitcoin_p2sh_address(input: &[u8]) -> bool {
    if input.len() != 33 {
        return false;
    }

    let decoded_input = bs58::decode(&[&[b'3'], input].concat()).into_vec().unwrap();

    let (data, checksum) = decoded_input.split_at(21);

    let mut sha256 = Sha256::new();
    sha256.update(data);
    let hash = sha256.finalize();

    let mut pass2 = Sha256::new();
    pass2.update(hash);
    let hash2 = pass2.finalize();

    hash2.to_vec().starts_with(checksum)
}

pub(crate) fn is_valid_bitcoin_p2wpkh_address(input: &[u8]) -> bool {
    if input.len() != 42 {
        return false;
    }

    let Ok((hrp, data)) = bech32::decode(std::str::from_utf8(input).unwrap()) else {
        return false;
    };

    if hrp != *BC_HRP && hrp != *TB_HRP {
        return false;
    }

    data.len() == 20
}

pub(crate) fn is_valid_bitcoin_p2wsh_address(input: &[u8]) -> bool {
    if input.len() != 62 {
        return false;
    }

    let Ok((hrp, data)) = bech32::decode(std::str::from_utf8(input).unwrap()) else {
        return false;
    };

    if hrp != *BC_HRP && hrp != *TB_HRP {
        return false;
    }

    data.len() == 33
}

pub(crate) fn is_valid_litecoin_p2wpkh_address(input: &[u8]) -> bool {
    if input.len() != 43 {
        return false;
    }

    let Ok((hrp, data)) = bech32::decode(std::str::from_utf8(input).unwrap()) else {
        return false;
    };

    hrp == *LTC_HRP && data.len() == 20
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_litecoin_p2wpkh_address() {
        assert!(is_valid_litecoin_p2wpkh_address(
            "ltc1q8c6fshw2dlwun7ekn9qwf37cu2rn755u9ym7p0".as_bytes()
        ))
    }

    #[test]
    fn test_is_valid_bitcoin_p2pkh_address() {
        assert!(is_valid_bitcoin_p2pkh_address(
            "A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".as_bytes()
        ));
    }

    #[test]
    fn test_is_invalid_bitcoin_p2pkh_address() {
        assert!(!is_valid_bitcoin_p2pkh_address(
            "A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb".as_bytes()
        ));
        assert!(!is_valid_bitcoin_p2pkh_address(
            "JQ1hGRjZ3UDYzMnM3UUdxeEY2ST".as_bytes()
        ));
    }

    #[test]
    fn test_is_valid_bitcoin_p2sh_address() {
        assert!(is_valid_bitcoin_p2sh_address(
            "2jmM9eev8E7CGCAWLSHQnqgHBifcHzgQf".as_bytes()
        ));
    }

    #[test]
    fn test_is_invalid_bitcoin_p2sh_address() {
        assert!(!is_valid_bitcoin_p2sh_address(
            "23kRcADNDuj76VjPEmgzAUk8fRx4bdVv8".as_bytes()
        ));
    }

    #[test]
    fn test_is_valid_bitcoin_p2wpkh_address() {
        assert!(is_valid_bitcoin_p2wpkh_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".as_bytes()
        ));
    }

    #[test]
    fn test_is_invalid_bitcoin_p2wpkh_address() {
        assert!(!is_valid_bitcoin_p2wpkh_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t".as_bytes()
        ));
    }

    #[test]
    fn test_is_valid_bitcoin_p2wpkh_testnet_address() {
        assert!(is_valid_bitcoin_p2wpkh_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".as_bytes()
        ));
    }

    #[test]
    fn test_is_valid_bitcoin_p2wsh_address() {
        assert!(is_valid_bitcoin_p2wsh_address(
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3".as_bytes()
        ));
    }

    #[test]
    fn test_is_invalid_bitcoin_p2wsh_address() {
        assert!(!is_valid_bitcoin_p2wsh_address(
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv".as_bytes()
        ));
    }

    #[test]
    fn test_is_valid_bitcoin_p2wsh_testnet_address() {
        assert!(is_valid_bitcoin_p2wsh_address(
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".as_bytes()
        ));
    }
}
