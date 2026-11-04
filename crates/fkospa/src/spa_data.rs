use std::fmt;

/// SPA data: the encrypted, base64-encoded string that travels on the wire
/// as the payload of an SPA packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpaData(String);

impl SpaData {
    /// Wraps a received or stored SPA data string. Nothing is checked until
    /// it is decrypted.
    pub fn new(data: impl Into<String>) -> SpaData {
        SpaData(data.into())
    }

    /// SPA data from a received datagram's bytes. Bytes that are not UTF-8
    /// cannot be valid SPA data and are replaced, so decryption fails.
    pub fn from_bytes(bytes: &[u8]) -> SpaData {
        SpaData(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for SpaData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for SpaData {
    fn from(s: String) -> SpaData {
        SpaData(s)
    }
}

impl AsRef<str> for SpaData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
