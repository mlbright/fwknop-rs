//! Base64 the way fwknop uses it.
//!
//! SPA fields and digests use the standard alphabet with the trailing `=`
//! padding stripped. Decoding follows fwknop-go exactly: padding is re-added
//! up to a multiple of four, then the string is decoded like Go's
//! `base64.StdEncoding`, which ignores `\r` and `\n` and tolerates non-zero
//! trailing bits.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, Engine, GeneralPurpose, GeneralPurposeConfig};

/// Standard alphabet, no padding on output.
const SPA: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_encode_padding(false),
);

/// Go's `base64.StdEncoding` as a decoder: padding required, trailing bits
/// not checked.
const GO_STD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

/// Standard alphabet with padding, for keys.
const STD: GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// SPA-style encoding: standard base64 without trailing `=`.
pub(crate) fn encode(data: &[u8]) -> String {
    SPA.encode(data)
}

/// SPA-style decoding: accepts input with or without trailing `=`.
pub(crate) fn decode(s: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    let mut padded = s.to_vec();
    let rem = padded.len() % 4;
    if rem != 0 {
        padded.resize(padded.len() + 4 - rem, b'=');
    }
    decode_go_std(&padded)
}

/// Decodes like Go's `base64.StdEncoding.DecodeString`.
pub(crate) fn decode_go_std(s: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    if s.contains(&b'\r') || s.contains(&b'\n') {
        let stripped: Vec<u8> = s
            .iter()
            .copied()
            .filter(|&c| c != b'\r' && c != b'\n')
            .collect();
        return GO_STD.decode(stripped);
    }
    GO_STD.decode(s)
}

/// Standard base64 with padding.
pub(crate) fn encode_std(data: &[u8]) -> String {
    STD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors from the C implementation's base64.c unit tests.
    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn encode_strips_padding() {
        for (input, padded) in VECTORS {
            assert_eq!(encode(input.as_bytes()), padded.trim_end_matches('='));
        }
    }

    #[test]
    fn decode_with_padding() {
        for (want, input) in VECTORS {
            assert_eq!(decode(input.as_bytes()).unwrap(), want.as_bytes());
        }
    }

    #[test]
    fn decode_without_padding() {
        for (input, want) in [
            ("Zg", "f"),
            ("Zm8", "fo"),
            ("Zm9vYg", "foob"),
            ("Zm9vYmE", "fooba"),
        ] {
            assert_eq!(decode(input.as_bytes()).unwrap(), want.as_bytes());
        }
    }

    #[test]
    fn round_trip() {
        for input in [
            "",
            "a",
            "ab",
            "abc",
            "abcd",
            "Hello, World!",
            "SPA test data 123",
        ] {
            assert_eq!(
                decode(encode(input.as_bytes()).as_bytes()).unwrap(),
                input.as_bytes()
            );
        }
    }

    #[test]
    fn go_std_requires_padding_and_ignores_newlines() {
        assert!(decode_go_std(b"Zg").is_err());
        assert_eq!(decode_go_std(b"Zm9v\nYmFy\r\n").unwrap(), b"foobar");
        // Go does not check that the unused bits of the last character are zero.
        assert_eq!(decode_go_std(b"Zh==").unwrap(), b"f");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode(b"!!!!").is_err());
        assert!(decode(b"Z").is_err());
    }
}
