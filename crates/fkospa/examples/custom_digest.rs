//! Use different digest and HMAC algorithms.
//!
//! Run with `cargo run -p fkospa --example custom_digest`.

use fkospa::{
    DigestType, EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage,
};

fn main() -> Result<(), fkospa::Error> {
    // Digest types: Md5, Sha1, Sha256 (default), Sha384, Sha512, Sha3_256,
    // Sha3_512. HMAC types mirror them. The server detects the digest type
    // from its length, but must be configured with the same HMAC type.
    let configs = [
        ("SHA-512", DigestType::Sha512, HmacType::Sha512),
        ("SHA3-256", DigestType::Sha3_256, HmacType::Sha3_256),
        ("MD5 (not recommended)", DigestType::Md5, HmacType::Md5),
    ];

    for (name, digest, hmac) in configs {
        let keys = KeySet::new(
            EncryptionKey::new("my_encryption_key"),
            EncryptionMode::Cbc,
            Some(HmacKey::new("my_hmac_key", hmac)),
        );
        let mut msg = SpaMessage::new(Request::access("10.0.0.1,tcp/22".parse()?))?;
        msg.username = "alice".into();
        msg.digest_type = digest;
        let spa_data = msg.encrypt(&keys)?;

        let decoded = SpaMessage::decrypt(&spa_data, &keys)?;
        println!(
            "{name:<25}  digest={}  hmac={hmac}  SPA length={}",
            decoded.digest_type,
            spa_data.len()
        );
    }
    Ok(())
}
