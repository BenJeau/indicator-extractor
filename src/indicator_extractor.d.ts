
/**
 * Extract indicators (IP, domain, email, hashes, Bicoin addresses, Litecoin addresses, etc.) from an array of bytes.
 * @param {Uint8Array} input
 * @returns {Indicator[]}
 */
export function extractIndicatorsBytes(input: Uint8Array): Indicator[];

/**
 * Extract indicators (IP, domain, email, hashes, Bicoin addresses, Litecoin addresses, etc.) from a string, uses `extractIndicatorsBytes` internally.
 * @param {string} input
 * @returns {Indicator[]}
 */
export function extractIndicators(input: string): Indicator[];

/**
 * Data representing a single indicator with a kind and a value.
 *
 * If the value contained defanged data, the fangs will be removed. Meaning that `https[:]//github(.)com` will be represented as `Url("https://github.com")`.
 */
export type Indicator = {
  /** Indicator kind, expressing the kind of data contained in the value field */
  kind: IndicatorKind;
  /** Stringified representation of the indicator value */
  value: string;
};

/** Indicator kind */
export enum IndicatorKind {
  /** An URL starting with `http` or `https` */
  Url = "url",
  /** A domain name with a valid TLD (e.g., `github.com`) with validation using [tldextract](https://github.com/john-kurkowski/tldextract) */
  Domain = "domain",
  /** A filename with very basic validation (e.g. if it has a `.`), but no extension validation. It's not guaranteed to be a valid filename and is mostly a catch-all if it wasn't able to match any other indicator. */
  File = "file",
  /** An email address, e.g. `benoit@jeaurond.dev` */
  Email = "email",
  /** An IPv4 address, e.g. `127.0.0.1` */
  Ipv4 = "ipv4",
  /** An IPv6 address, e.g. `2001:0db8:85a3:0000:0000:8a2e:0370:7334` */
  Ipv6 = "ipv6",
  /** A case-insentive SHA512 hash, e.g. `f1d9d8f153ec808a44cd63fb85f7cb811845b1596e46e78febd8c8b505a9b7d3a242c98b2b51261e5402f37334beefd7ba4066873a6dc56cd030cf29f4aef6dc` */
  Sha512 = "sha512",
  /** A case-insentive SHA256 hash, e.g. `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` */
  Sha256 = "sha256",
  /** A case-insentive SHA1 hash, e.g. `da39a3ee5e6b4b0d3255bfef95601890afd80709` */
  Sha1 = "sha1",
  /** A case-insentive MD5 hash, e.g. `d41d8cd98f00b204e9800998ecf8427e` */
  Md5 = "md5",
  /** A Bitcoin [P2PKH](https://learnmeabitcoin.com/technical/script/p2pkh/) address, e.g. `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` */
  BitcoinP2pkhAddress = "bitcoin_p2pkh_address",
  /** A Bitcoin [P2SH](https://learnmeabitcoin.com/technical/script/p2sh/) address, e.g. `32jmM9eev8E7CGCAWLSHQnqgHBifcHzgQf` */
  BitcoinP2shAddress = "bitcoin_p2sh_address",
  /** A Bitcoin [P2WPKH](https://learnmeabitcoin.com/technical/script/p2wpkh/) address, e.g. `bc1p4w46h2at4w46h2at4w46h2at4w46h2at5kreae` */
  BitcoinP2wpkhAddress = "bitcoin_p2wpkh_address",
  /** A Bitcoin [P2WSH](https://learnmeabitcoin.com/technical/script/p2wsh/) address, e.g. `bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3` */
  BitcoinP2wshAddress = "bitcoin_p2wsh_address",
  /** A Litecoin P2WPKH address, e.g. `ltc1q8c6fshw2dlwun7ekn9qwf37cu2rn755u9ym7p0` */
  LitecoinP2wpkhAddress = "litecoin_p2wpkh_address",
}
