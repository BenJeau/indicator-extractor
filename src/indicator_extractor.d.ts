
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

/// Data representing a single indicator
export type Indicator = {
  /// Indicator kind, expressing the kind of data contained in the value field
  kind: IndicatorKind;
  /// Stringified representation of the indicator value
  value: string;
};

/// Indicator kind
export type IndicatorKind =
  | "url"
  | "domain"
  | "file"
  | "email"
  | "ipv4"
  | "ipv6"
  | "sha512"
  | "sha256"
  | "sha1"
  | "md5"
  | "bitcoin_p2pkh_address"
  | "bitcoin_p2sh_address"
  | "bitcoin_p2wpkh_address"
  | "bitcoin_p2wsh_address"
  | "litecoin_p2pkh_address"
  | "litecoin_p2wpkh_address";
