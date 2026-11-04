//! The keys and modes a client and an access stanza must share.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algorithms::{EncryptionMode, HmacType};
use crate::b64;
use crate::error::Error;

/// The encryption key (the passphrase fed to key derivation). Its bytes are
/// wiped from memory when it is dropped, and `Debug` shows only its length.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey(Vec<u8>);

impl EncryptionKey {
    /// A key from raw bytes (a plaintext passphrase, or already-decoded
    /// base64).
    pub fn new(bytes: impl Into<Vec<u8>>) -> EncryptionKey {
        EncryptionKey(bytes.into())
    }

    /// A key from standard base64, as in `--key-base64` and `key_base64`.
    pub fn from_base64(s: &str) -> Result<EncryptionKey, Error> {
        decode_base64_key(s).map(EncryptionKey)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptionKey(<{} bytes>)", self.0.len())
    }
}

/// An HMAC key and the HMAC type it is used with. The key bytes are wiped
/// from memory when it is dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HmacKey {
    key: Vec<u8>,
    #[zeroize(skip)]
    hmac_type: HmacType,
}

impl HmacKey {
    pub fn new(key: impl Into<Vec<u8>>, hmac_type: HmacType) -> HmacKey {
        HmacKey {
            key: key.into(),
            hmac_type,
        }
    }

    /// A key from standard base64, as in `--key-base64-hmac` and
    /// `hmac_key_base64`.
    pub fn from_base64(s: &str, hmac_type: HmacType) -> Result<HmacKey, Error> {
        decode_base64_key(s).map(|key| HmacKey::new(key, hmac_type))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn len(&self) -> usize {
        self.key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    pub fn hmac_type(&self) -> HmacType {
        self.hmac_type
    }
}

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HmacKey(<{} bytes>, {})", self.key.len(), self.hmac_type)
    }
}

/// The encryption key, encryption mode and optional HMAC key and type that a
/// client and an access stanza must share for a packet to be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    pub encryption_key: EncryptionKey,
    pub encryption_mode: EncryptionMode,
    /// `None` sends (or accepts) SPA data without an HMAC.
    pub hmac: Option<HmacKey>,
}

impl KeySet {
    pub fn new(
        encryption_key: EncryptionKey,
        encryption_mode: EncryptionMode,
        hmac: Option<HmacKey>,
    ) -> KeySet {
        KeySet {
            encryption_key,
            encryption_mode,
            hmac,
        }
    }
}

/// Decodes a base64 key the way fwknop-go does (standard alphabet, padding
/// required).
pub fn decode_base64_key(s: &str) -> Result<Vec<u8>, Error> {
    b64::decode_go_std(s.as_bytes())
        .map_err(|e| Error::InvalidData(format!("invalid base64 key: {e}")))
}

/// Generates `len` random bytes for an encryption or HMAC key and returns
/// them as standard base64 (with padding), the form `--key-gen` prints.
pub fn generate_key(len: usize) -> Result<String, Error> {
    if len == 0 {
        return Err(Error::InvalidKeyLen("key length must be positive".into()));
    }
    let mut key = zeroize::Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut key).map_err(|e| Error::Random(e.to_string()))?;
    Ok(b64::encode_std(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_key_bytes() {
        let key = EncryptionKey::new(b"supersecret".to_vec());
        assert_eq!(format!("{key:?}"), "EncryptionKey(<11 bytes>)");
        let hmac = HmacKey::new(b"hmacsecret".to_vec(), HmacType::Sha256);
        assert_eq!(format!("{hmac:?}"), "HmacKey(<10 bytes>, HMAC-SHA256)");
    }

    #[test]
    fn base64_keys() {
        let key =
            EncryptionKey::from_base64("bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=").unwrap();
        assert_eq!(key.len(), 32);
        assert!(EncryptionKey::from_base64("not base64!").is_err());
        // Go's StdEncoding requires padding.
        assert!(EncryptionKey::from_base64("Zg").is_err());
    }

    #[test]
    fn generated_keys_have_requested_length() {
        let a = generate_key(32).unwrap();
        let b = generate_key(32).unwrap();
        assert_ne!(a, b);
        assert_eq!(decode_base64_key(&a).unwrap().len(), 32);
        assert_eq!(
            decode_base64_key(&generate_key(1).unwrap()).unwrap().len(),
            1
        );
        assert!(matches!(generate_key(0), Err(Error::InvalidKeyLen(_))));
    }
}
