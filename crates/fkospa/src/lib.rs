//! The fwknop Single Packet Authorization (SPA) protocol.
//!
//! SPA lets a client ask a server to open firewall access with one
//! encrypted, authenticated, non-replayable UDP packet, while the server's
//! services stay hidden behind a default-drop firewall. This crate builds,
//! encrypts, decrypts and decodes SPA messages compatible with C fwknop and
//! fwknop-go (protocol 3.0.0). It does no networking; see the `fwknop` crate
//! for sending a knock.
//!
//! # Building and encrypting an SPA message
//!
//! [`SpaMessage::new`] fills in a random value, the current user, the
//! current time and a SHA-256 message digest. Fields are public, so override
//! any of them directly.
//!
//! ```
//! use fkospa::{AccessMessage, EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet,
//!              Request, SpaMessage};
//!
//! let access: AccessMessage = "192.168.1.1,tcp/22".parse()?;
//! let mut msg = SpaMessage::new(Request::access(access))?;
//! msg.username = "alice".into();
//!
//! let keys = KeySet::new(
//!     EncryptionKey::new("my_encryption_key"),
//!     EncryptionMode::Cbc,
//!     Some(HmacKey::new("my_hmac_key", HmacType::Sha256)),
//! );
//! let spa_data = msg.encrypt(&keys)?;
//! // spa_data is what goes in the UDP packet to the fwknopd server.
//! assert!(!spa_data.is_empty());
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # Decrypting and decoding received SPA data
//!
//! ```
//! use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, MessageType,
//!              Request, SpaMessage};
//!
//! let keys = KeySet::new(
//!     EncryptionKey::new("shared_secret"),
//!     EncryptionMode::Cbc,
//!     Some(HmacKey::new("hmac_secret", HmacType::Sha256)),
//! );
//! let mut sent = SpaMessage::new(Request::access("10.0.0.1,tcp/22".parse()?))?;
//! sent.rand_val = "1234567890123456".parse()?;
//! sent.username = "bob".into();
//! sent.timestamp = 1_700_000_000;
//! let spa_data = sent.encrypt(&keys)?;
//!
//! // Server side:
//! let received = SpaMessage::decrypt(&spa_data, &keys)?;
//! assert_eq!(received.username, "bob");
//! assert_eq!(received.request.message_text(), "10.0.0.1,tcp/22");
//! assert_eq!(received.message_type(), MessageType::Access);
//! assert_eq!(received, sent);
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # Defaults
//!
//! ```
//! use fkospa::{DigestType, EncryptionMode, HmacType, MessageType, Request, SpaMessage};
//!
//! let msg = SpaMessage::new(Request::access("192.168.1.1,tcp/22".parse()?))?;
//! assert_eq!(msg.message_type().to_string(), "Access");
//! assert_eq!(msg.digest_type.to_string(), "SHA256");
//! assert_eq!(EncryptionMode::default().to_string(), "CBC");
//! assert_eq!(HmacType::default(), HmacType::Sha256);
//! assert_eq!(msg.rand_val.as_str().len(), 16);
//! assert!(!msg.username.is_empty());
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # Choosing the digest
//!
//! ```
//! use fkospa::{DigestType, Request, SpaMessage};
//!
//! let mut msg = SpaMessage::new(Request::access("10.0.0.1,tcp/22".parse()?))?;
//! msg.username = "alice".into();
//! msg.digest_type = DigestType::Sha512;
//! assert_eq!(msg.username, "alice");
//! assert_eq!(msg.request.message_text(), "10.0.0.1,tcp/22");
//! assert_eq!(msg.digest_type.to_string(), "SHA512");
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # The plaintext before encryption
//!
//! [`SpaMessage::encode`] shows exactly what gets encrypted:
//!
//! ```text
//! RAND_VAL:B64(USERNAME):TIMESTAMP:VERSION:MSG_TYPE:B64(MESSAGE)[:B64(NAT_ACCESS)][:B64(SERVER_AUTH)][:CLIENT_TIMEOUT]:DIGEST
//! ```
//!
//! ```
//! use fkospa::{Request, SpaMessage};
//!
//! let mut msg = SpaMessage::new(Request::access("192.168.1.1,tcp/22".parse()?))?;
//! msg.rand_val = "1234567890123456".parse()?;
//! msg.username = "alice".into();
//! msg.timestamp = 1_700_000_000;
//! assert_eq!(
//!     msg.encode()?,
//!     "1234567890123456:YWxpY2U:1700000000:3.0.0:1:MTkyLjE2OC4xLjEsdGNwLzIy:\
//!      InhdiYP3+F4uF1ShX9rkUs/lL8N86cJPn4VWjmXpU1w"
//! );
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # Generating keys
//!
//! ```
//! let key = fkospa::generate_key(32)?;
//! assert_eq!(key.len(), 44); // standard base64 of 32 bytes
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # NAT access
//!
//! ```
//! use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, MessageType,
//!              Request, SpaMessage};
//!
//! let keys = KeySet::new(
//!     EncryptionKey::new("key"),
//!     EncryptionMode::Cbc,
//!     Some(HmacKey::new("hmac", HmacType::Sha256)),
//! );
//! let msg = SpaMessage::new(Request::NatAccess {
//!     access: "192.168.1.1,tcp/22".parse()?,
//!     nat_access: "10.0.0.100,22".into(),
//!     client_timeout: None,
//! })?;
//! let decoded = SpaMessage::decrypt(&msg.encrypt(&keys)?, &keys)?;
//! assert_eq!(decoded.message_type(), MessageType::NatAccess);
//! assert_eq!(decoded.request.nat_access(), Some("10.0.0.100,22"));
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # Client timeout
//!
//! A client timeout turns an access request into its client-timeout message
//! type:
//!
//! ```
//! use std::num::NonZeroU32;
//! use fkospa::{EncryptionKey, EncryptionMode, KeySet, MessageType, Request, SpaMessage};
//!
//! let keys = KeySet::new(EncryptionKey::new("key"), EncryptionMode::Cbc, None);
//! let msg = SpaMessage::new(Request::Access {
//!     access: "10.0.0.1,tcp/22".parse()?,
//!     client_timeout: NonZeroU32::new(30),
//! })?;
//! let decoded = SpaMessage::decrypt(&msg.encrypt(&keys)?, &keys)?;
//! assert_eq!(decoded.message_type(), MessageType::ClientTimeoutAccess);
//! assert_eq!(decoded.request.client_timeout(), NonZeroU32::new(30));
//! # Ok::<(), fkospa::Error>(())
//! ```
//!
//! # Wire format
//!
//! The plaintext above is encrypted with AES-256-CBC in OpenSSL's
//! `Salted__` format, the key and IV derived from the encryption key by
//! `EVP_BytesToKey` (MD5). The ciphertext is base64-encoded without padding,
//! its constant `U2FsdGVkX1` prefix (base64 of `Salted__`) is removed, and
//! the HMAC, computed over the base64 *with* the prefix, is appended.

mod algorithms;
mod b64;
mod cipher;
mod error;
mod keys;
mod message;
mod spa_data;
mod user;

#[cfg(test)]
mod tests;

pub use algorithms::{DigestType, EncryptionMode, HmacType};
pub use error::Error;
pub use keys::{EncryptionKey, HmacKey, KeySet, decode_base64_key, generate_key};
pub use message::{
    AccessMessage, AccessSpec, MessageType, PROTOCOL_VERSION, Proto, RandVal, Request, SpaMessage,
};
pub use spa_data::SpaData;

/// This crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
