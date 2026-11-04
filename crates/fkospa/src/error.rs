/// Everything that can go wrong while building, encrypting, decrypting or
/// decoding an SPA message.
///
/// The variants mirror fwknop-go's sentinel errors (`ErrInvalidData`,
/// `ErrHMACVerificationFailed`, …) so log messages read the same; the
/// string payloads carry the detail Go appended with `fmt.Errorf("%w: …")`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Input data is malformed or out of range.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// The encoded SPA message is outside the allowed size range.
    #[error("message too large: {0}")]
    MessageTooLarge(String),

    /// A required field is empty.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// The message digest of the decrypted SPA message does not match.
    #[error("digest verification failed")]
    DigestVerificationFailed,

    /// The HMAC on the SPA data does not match (or there is none).
    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    /// The SPA data could not be decoded or decrypted.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// An encryption mode name is not one fwknop-rs supports.
    #[error("unsupported encryption mode: {0}")]
    UnsupportedEncryptionMode(String),

    /// A key has an unusable length.
    #[error("invalid key length: {0}")]
    InvalidKeyLen(String),

    /// A digest name or digest length is not recognised.
    #[error("unsupported digest type: {0}")]
    UnsupportedDigestType(String),

    /// An HMAC name is not recognised.
    #[error("unsupported HMAC type: {0}")]
    UnsupportedHmacType(String),

    /// The operating system's random number generator failed.
    #[error("generating random data: {0}")]
    Random(String),

    /// The current user's name could not be determined.
    #[error("detecting username: {0}")]
    Username(String),
}

pub(crate) fn invalid(detail: impl Into<String>) -> Error {
    Error::InvalidData(detail.into())
}

pub(crate) fn missing(detail: impl Into<String>) -> Error {
    Error::MissingField(detail.into())
}
