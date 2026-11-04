//! AES-256-CBC in OpenSSL's `Salted__` format, as C fwknop produces it.
//!
//! The ciphertext is `"Salted__" || salt (8 bytes) || AES-256-CBC(plaintext)`,
//! with the key and IV derived from the encryption key and salt by OpenSSL's
//! `EVP_BytesToKey` (MD5, one iteration).

use cbc::cipher::block_padding::{NoPadding, Pkcs7};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::digest::Digest;

use crate::algorithms::EncryptionMode;
use crate::error::Error;

const SALTED: &[u8; 8] = b"Salted__";
pub(crate) const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const BLOCK: usize = 16;
/// Legacy-IV mode pads encryption keys shorter than this with `'0'`.
const LEGACY_MIN_KEY: usize = 16;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// OpenSSL's `EVP_BytesToKey` with MD5 and one iteration: hash
/// `prev || passphrase || salt` repeatedly until there are enough bytes for
/// the key and IV.
pub(crate) fn evp_bytes_to_key(passphrase: &[u8], salt: &[u8]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
    let mut material = Vec::with_capacity(KEY_LEN + IV_LEN + 16);
    let mut prev: Vec<u8> = Vec::new();
    while material.len() < KEY_LEN + IV_LEN {
        let mut h = md5::Md5::new();
        h.update(&prev);
        h.update(passphrase);
        h.update(salt);
        prev = h.finalize().to_vec();
        material.extend_from_slice(&prev);
    }
    let mut key = [0u8; KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    key.copy_from_slice(&material[..KEY_LEN]);
    iv.copy_from_slice(&material[KEY_LEN..KEY_LEN + IV_LEN]);
    zeroize::Zeroize::zeroize(&mut material);
    (key, iv)
}

/// Pads a short key with `'0'` up to 16 bytes, as old fwknop clients did.
fn legacy_pad(passphrase: &[u8]) -> Vec<u8> {
    let mut padded = passphrase.to_vec();
    if padded.len() < LEGACY_MIN_KEY {
        padded.resize(LEGACY_MIN_KEY, b'0');
    }
    padded
}

fn effective_key(mode: EncryptionMode, passphrase: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(match mode {
        EncryptionMode::Cbc => passphrase.to_vec(),
        EncryptionMode::CbcLegacyIv => legacy_pad(passphrase),
    })
}

/// Encrypts with a random salt.
pub(crate) fn encrypt(
    mode: EncryptionMode,
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| Error::Random(e.to_string()))?;
    Ok(encrypt_with_salt(mode, plaintext, passphrase, &salt))
}

pub(crate) fn encrypt_with_salt(
    mode: EncryptionMode,
    plaintext: &[u8],
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
) -> Vec<u8> {
    let key = effective_key(mode, passphrase);
    let (mut aes_key, mut iv) = evp_bytes_to_key(&key, salt);
    let ciphertext =
        Aes256CbcEnc::new(&aes_key.into(), &iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext);
    zeroize::Zeroize::zeroize(&mut aes_key);
    zeroize::Zeroize::zeroize(&mut iv);

    let mut out = Vec::with_capacity(2 * SALT_LEN + ciphertext.len());
    out.extend_from_slice(SALTED);
    out.extend_from_slice(salt);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts data produced by [`encrypt`].
///
/// Like C fwknop, invalid PKCS#7 padding is not an error: the plaintext is
/// returned unpadded-as-is and the message digest catches the damage.
pub(crate) fn decrypt(
    mode: EncryptionMode,
    data: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, Error> {
    if data.len() < 2 * SALT_LEN + BLOCK {
        return Err(Error::DecryptionFailed("ciphertext too short".into()));
    }
    if &data[..SALT_LEN] != SALTED {
        return Err(Error::DecryptionFailed("missing Salted__ prefix".into()));
    }
    let salt = &data[SALT_LEN..2 * SALT_LEN];
    let ciphertext = &data[2 * SALT_LEN..];
    if !ciphertext.len().is_multiple_of(BLOCK) {
        return Err(Error::DecryptionFailed(
            "ciphertext not block-aligned".into(),
        ));
    }

    let key = effective_key(mode, passphrase);
    let (mut aes_key, mut iv) = evp_bytes_to_key(&key, salt);
    let plaintext = Aes256CbcDec::new(&aes_key.into(), &iv.into())
        .decrypt_padded_vec::<NoPadding>(ciphertext)
        .map_err(|_| Error::DecryptionFailed("ciphertext not block-aligned".into()))?;
    zeroize::Zeroize::zeroize(&mut aes_key);
    zeroize::Zeroize::zeroize(&mut iv);

    let len = pkcs7_unpadded_len(&plaintext);
    let mut plaintext = plaintext;
    plaintext.truncate(len);
    Ok(plaintext)
}

/// Length of `data` without its PKCS#7 padding, or the whole length when the
/// padding is invalid (C fwknop's tolerance).
fn pkcs7_unpadded_len(data: &[u8]) -> usize {
    let Some(&last) = data.last() else {
        return 0;
    };
    let pad = usize::from(last);
    if pad == 0 || pad > BLOCK || pad > data.len() {
        return data.len();
    }
    let start = data.len() - pad;
    if data[start..].iter().all(|&b| b == last) {
        start
    } else {
        data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    #[test]
    fn evp_bytes_to_key_matches_openssl() {
        // openssl enc -aes-256-cbc -P -S 0000000000000000 -pass pass:testpass -md md5
        let (key, iv) = evp_bytes_to_key(b"testpass", &[0; 8]);
        assert_eq!(
            hex(&key),
            "5ABA86CFD22C69B24074F9B33C262890C444329795A36DF0CAA45934EA67C8B9"
        );
        assert_eq!(hex(&iv), "1EAEE6337DF72986F11C51473B16EFB6");
    }

    #[test]
    fn evp_bytes_to_key_depends_on_password_and_salt() {
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_ne!(
            evp_bytes_to_key(b"password1", &salt).0,
            evp_bytes_to_key(b"password2", &salt).0
        );
        assert_ne!(
            evp_bytes_to_key(b"testpass", &salt).0,
            evp_bytes_to_key(b"testpass", &[8, 7, 6, 5, 4, 3, 2, 1]).0
        );
    }

    #[test]
    fn legacy_mode_pads_short_keys_with_zero_characters() {
        // openssl enc -aes-256-cbc -P -S 0102030405060708 -pass pass:abc0000000000000 -md md5
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let (key, iv) =
            evp_bytes_to_key(&effective_key(EncryptionMode::CbcLegacyIv, b"abc"), &salt);
        assert_eq!(
            hex(&key),
            "AAF70138B464B07CF6847A646732668FE65FE33D3B24C4FAA75DE74B96F76CD7"
        );
        assert_eq!(hex(&iv), "7AD4CA0B7C00A84D8F3F965ACD9C8FEE");

        for (input, want) in [
            ("abc", "abc0000000000000"),
            ("1234567890123456", "1234567890123456"),
            ("longpassphrase!!", "longpassphrase!!"),
            ("verylongpassphrase", "verylongpassphrase"),
        ] {
            assert_eq!(legacy_pad(input.as_bytes()), want.as_bytes());
        }
    }

    #[test]
    fn cbc_round_trip() {
        let plaintext = b"Hello, SPA world! This is a test message.";
        for mode in [EncryptionMode::Cbc, EncryptionMode::CbcLegacyIv] {
            let ct = encrypt(mode, plaintext, b"test encryption key").unwrap();
            assert_eq!(&ct[..8], b"Salted__");
            assert_eq!(
                decrypt(mode, &ct, b"test encryption key").unwrap(),
                plaintext
            );
        }
        let ct = encrypt(
            EncryptionMode::CbcLegacyIv,
            b"Legacy IV test data",
            b"short",
        )
        .unwrap();
        assert_eq!(
            decrypt(EncryptionMode::CbcLegacyIv, &ct, b"short").unwrap(),
            b"Legacy IV test data"
        );
    }

    #[test]
    fn wrong_key_does_not_recover_plaintext() {
        let ct = encrypt(EncryptionMode::Cbc, b"secret message", b"correct key").unwrap();
        if let Ok(pt) = decrypt(EncryptionMode::Cbc, &ct, b"wrong key") {
            assert_ne!(pt, b"secret message");
        }
    }

    #[test]
    fn fixed_salt_is_deterministic() {
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let a = encrypt_with_salt(
            EncryptionMode::Cbc,
            b"deterministic test",
            b"testkey",
            &salt,
        );
        let b = encrypt_with_salt(
            EncryptionMode::Cbc,
            b"deterministic test",
            b"testkey",
            &salt,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn matches_openssl_ciphertext() {
        // printf 'deterministic test' | openssl enc -aes-256-cbc -S 0102030405060708 \
        //     -pass pass:testkey -md md5 | xxd -p
        // (OpenSSL 3+ omits the Salted__ header when the salt is given with -S.)
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let ct = encrypt_with_salt(
            EncryptionMode::Cbc,
            b"deterministic test",
            b"testkey",
            &salt,
        );
        assert_eq!(hex(&ct[..16]), "53616C7465645F5F0102030405060708");
        assert_eq!(
            hex(&ct[16..]),
            "949F92BE8C27BAB2360346E86C9D02FE5203AC80783D0E1987F39B5D08FA3FE2"
        );
    }

    #[test]
    fn padding_round_trips_for_every_length() {
        for len in 0..50 {
            let data = vec![b'A'; len];
            let ct = encrypt(EncryptionMode::Cbc, &data, b"k").unwrap();
            assert_eq!((ct.len() - 16) % 16, 0);
            assert_eq!(decrypt(EncryptionMode::Cbc, &ct, b"k").unwrap(), data);
        }
    }

    #[test]
    fn invalid_padding_is_tolerated() {
        assert_eq!(pkcs7_unpadded_len(&[]), 0);
        assert_eq!(pkcs7_unpadded_len(&[b'a', 0]), 2);
        assert_eq!(pkcs7_unpadded_len(&[b'a', 17]), 2);
        assert_eq!(pkcs7_unpadded_len(&[b'a', 1, 2]), 3);
        assert_eq!(pkcs7_unpadded_len(&[b'a', 2, 2]), 1);
    }

    #[test]
    fn rejects_malformed_ciphertext() {
        assert!(decrypt(EncryptionMode::Cbc, b"short", b"k").is_err());
        assert!(decrypt(EncryptionMode::Cbc, &[0u8; 48], b"k").is_err());
        let mut bad = b"Salted__".to_vec();
        bad.extend_from_slice(&[0u8; 8 + 17]);
        assert!(decrypt(EncryptionMode::Cbc, &bad, b"k").is_err());
    }
}
