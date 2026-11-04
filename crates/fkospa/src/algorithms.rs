//! The digest, HMAC and encryption algorithms an SPA message can use.

use std::fmt;
use std::str::FromStr;

use hmac::digest::Digest;
use hmac::digest::common::BlockSizeUser;
use hmac::{KeyInit, Mac, SimpleHmac};

use crate::b64;
use crate::error::Error;

/// The hash used for an SPA message's message digest.
///
/// The server does not need to be told which one a client used: it is
/// recognised from the digest's length (SHA-256 and SHA3-256 share a length,
/// as do SHA-512 and SHA3-512, and both are tried).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DigestType {
    Md5,
    Sha1,
    #[default]
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl DigestType {
    /// Every digest type, in fwknop's numbering order.
    pub const ALL: [DigestType; 7] = [
        DigestType::Md5,
        DigestType::Sha1,
        DigestType::Sha256,
        DigestType::Sha384,
        DigestType::Sha512,
        DigestType::Sha3_256,
        DigestType::Sha3_512,
    ];

    /// The raw hash of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestType::Md5 => md5::Md5::digest(data).to_vec(),
            DigestType::Sha1 => sha1::Sha1::digest(data).to_vec(),
            DigestType::Sha256 => sha2::Sha256::digest(data).to_vec(),
            DigestType::Sha384 => sha2::Sha384::digest(data).to_vec(),
            DigestType::Sha512 => sha2::Sha512::digest(data).to_vec(),
            DigestType::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
            DigestType::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        }
    }

    /// The hash of `data` in SPA-style base64 (standard alphabet, no `=`
    /// padding), as it appears in an SPA message and as the server uses it
    /// for replay digests.
    pub fn digest_b64(self, data: &[u8]) -> String {
        b64::encode(&self.digest(data))
    }

    /// Length of [`digest_b64`](Self::digest_b64) output.
    pub(crate) fn b64_len(self) -> usize {
        match self {
            DigestType::Md5 => 22,
            DigestType::Sha1 => 27,
            DigestType::Sha256 | DigestType::Sha3_256 => 43,
            DigestType::Sha384 => 64,
            DigestType::Sha512 | DigestType::Sha3_512 => 86,
        }
    }
}

/// Formats like fwknop-go: `MD5`, `SHA1`, `SHA256`, …, `SHA3-256`.
impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DigestType::Md5 => "MD5",
            DigestType::Sha1 => "SHA1",
            DigestType::Sha256 => "SHA256",
            DigestType::Sha384 => "SHA384",
            DigestType::Sha512 => "SHA512",
            DigestType::Sha3_256 => "SHA3-256",
            DigestType::Sha3_512 => "SHA3-512",
        })
    }
}

/// Parses the names used in flags and config files, ignoring case:
/// `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `sha3_256` / `sha3-256`,
/// `sha3_512` / `sha3-512`.
impl FromStr for DigestType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        parse_hash_name(s)
            .map(|i| DigestType::ALL[i])
            .ok_or_else(|| Error::UnsupportedDigestType(s.to_string()))
    }
}

/// The hash used for an SPA packet's HMAC. Unlike the digest type, it is not
/// detectable from the packet, so both sides must be configured with the
/// same one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HmacType {
    Md5,
    Sha1,
    #[default]
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl HmacType {
    /// Every HMAC type, in fwknop's numbering order.
    pub const ALL: [HmacType; 7] = [
        HmacType::Md5,
        HmacType::Sha1,
        HmacType::Sha256,
        HmacType::Sha384,
        HmacType::Sha512,
        HmacType::Sha3_256,
        HmacType::Sha3_512,
    ];

    /// The HMAC of `data` under `key`.
    pub(crate) fn compute(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HmacType::Md5 => hmac::<md5::Md5>(key, data),
            HmacType::Sha1 => hmac::<sha1::Sha1>(key, data),
            HmacType::Sha256 => hmac::<sha2::Sha256>(key, data),
            HmacType::Sha384 => hmac::<sha2::Sha384>(key, data),
            HmacType::Sha512 => hmac::<sha2::Sha512>(key, data),
            HmacType::Sha3_256 => hmac::<sha3::Sha3_256>(key, data),
            HmacType::Sha3_512 => hmac::<sha3::Sha3_512>(key, data),
        }
    }

    /// The HMAC of `data` under `key` in SPA-style base64.
    pub(crate) fn compute_b64(self, key: &[u8], data: &[u8]) -> String {
        b64::encode(&self.compute(key, data))
    }

    /// Length of [`compute_b64`](Self::compute_b64) output.
    pub(crate) fn b64_len(self) -> usize {
        DigestType::ALL[self as usize].b64_len()
    }
}

/// Formats like fwknop-go: `HMAC-MD5`, `HMAC-SHA256`, …, `HMAC-SHA3-512`.
impl fmt::Display for HmacType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HMAC-{}", DigestType::ALL[*self as usize])
    }
}

/// Parses the same names as [`DigestType`].
impl FromStr for HmacType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        parse_hash_name(s)
            .map(|i| HmacType::ALL[i])
            .ok_or_else(|| Error::UnsupportedHmacType(s.to_string()))
    }
}

fn hmac<D>(key: &[u8], data: &[u8]) -> Vec<u8>
where
    D: Digest + BlockSizeUser,
{
    let mut mac =
        <SimpleHmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Index into `ALL` for a hash name.
fn parse_hash_name(s: &str) -> Option<usize> {
    Some(match s.to_ascii_lowercase().as_str() {
        "md5" => 0,
        "sha1" => 1,
        "sha256" => 2,
        "sha384" => 3,
        "sha512" => 4,
        "sha3_256" | "sha3-256" => 5,
        "sha3_512" | "sha3-512" => 6,
        _ => return None,
    })
}

/// How SPA messages are encrypted: AES-256-CBC with the key and IV derived
/// from the encryption key by OpenSSL's `EVP_BytesToKey`.
///
/// The mode is not on the wire, so both sides must be configured with the
/// same one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EncryptionMode {
    /// Standard AES-256-CBC.
    #[default]
    Cbc,
    /// AES-256-CBC with an encryption key shorter than 16 bytes padded with
    /// `'0'` characters first, for compatibility with old fwknop clients.
    CbcLegacyIv,
}

/// Formats like fwknop-go: `CBC`, `CBC-LegacyIV`.
impl fmt::Display for EncryptionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EncryptionMode::Cbc => "CBC",
            EncryptionMode::CbcLegacyIv => "CBC-LegacyIV",
        })
    }
}

/// Parses the names used in flags and config files, ignoring case: `cbc`
/// and `legacy`.
impl FromStr for EncryptionMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_ascii_lowercase().as_str() {
            "cbc" => Ok(EncryptionMode::Cbc),
            "legacy" => Ok(EncryptionMode::CbcLegacyIv),
            _ => Err(Error::UnsupportedEncryptionMode(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_names_parse_case_insensitively() {
        let cases = [
            ("md5", DigestType::Md5),
            ("SHA1", DigestType::Sha1),
            ("sha256", DigestType::Sha256),
            ("Sha384", DigestType::Sha384),
            ("sha512", DigestType::Sha512),
            ("sha3_256", DigestType::Sha3_256),
            ("sha3-256", DigestType::Sha3_256),
            ("SHA3_512", DigestType::Sha3_512),
            ("sha3-512", DigestType::Sha3_512),
        ];
        for (name, want) in cases {
            assert_eq!(name.parse::<DigestType>(), Ok(want), "{name}");
        }
        assert!(matches!(
            "sha999".parse::<DigestType>(),
            Err(Error::UnsupportedDigestType(_))
        ));
    }

    #[test]
    fn hmac_names_parse() {
        assert_eq!("sha3-512".parse::<HmacType>(), Ok(HmacType::Sha3_512));
        assert_eq!("MD5".parse::<HmacType>(), Ok(HmacType::Md5));
        assert!(matches!(
            "bogus".parse::<HmacType>(),
            Err(Error::UnsupportedHmacType(_))
        ));
    }

    #[test]
    fn encryption_mode_names_parse() {
        assert_eq!("cbc".parse::<EncryptionMode>(), Ok(EncryptionMode::Cbc));
        assert_eq!(
            "LEGACY".parse::<EncryptionMode>(),
            Ok(EncryptionMode::CbcLegacyIv)
        );
        // The stubbed modes fwknop-go defined but never implemented are gone.
        for name in ["ecb", "cfb", "pcbc", "ofb", "ctr"] {
            assert!(matches!(
                name.parse::<EncryptionMode>(),
                Err(Error::UnsupportedEncryptionMode(_))
            ));
        }
    }

    #[test]
    fn display_matches_go() {
        let digests: Vec<String> = DigestType::ALL.iter().map(|d| d.to_string()).collect();
        assert_eq!(
            digests,
            [
                "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-512"
            ]
        );
        assert_eq!(HmacType::Sha3_256.to_string(), "HMAC-SHA3-256");
        assert_eq!(EncryptionMode::Cbc.to_string(), "CBC");
        assert_eq!(EncryptionMode::CbcLegacyIv.to_string(), "CBC-LegacyIV");
    }

    #[test]
    fn b64_lengths_match_output() {
        for d in DigestType::ALL {
            assert_eq!(d.digest_b64(b"x").len(), d.b64_len(), "{d}");
        }
        for h in HmacType::ALL {
            assert_eq!(h.compute_b64(b"k", b"x").len(), h.b64_len(), "{h}");
        }
    }

    #[test]
    fn known_digests() {
        assert_eq!(
            DigestType::Sha256.digest_b64(b"abc"),
            "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
        );
        assert_eq!(DigestType::Md5.digest_b64(b"abc"), "kAFQmDzST7DWlj99KOF/cg");
    }

    #[test]
    fn known_hmac_sha256() {
        // RFC 4231 test case 2.
        let mac = HmacType::Sha256.compute(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
