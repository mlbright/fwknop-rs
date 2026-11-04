//! Create, encrypt and decrypt an SPA message.
//!
//! Run with `cargo run -p fkospa --example basic_spa`.

use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage};

fn main() -> Result<(), fkospa::Error> {
    // Shared keys (in production, use base64 keys from `fwknop --key-gen`).
    let keys = KeySet::new(
        EncryptionKey::new("my_encryption_key"),
        EncryptionMode::Cbc,
        Some(HmacKey::new("my_hmac_key", HmacType::Sha256)),
    );

    // --- Client side: create and encrypt ---
    let mut msg = SpaMessage::new(Request::access("192.168.1.50,tcp/22".parse()?))?;
    msg.username = "alice".into();
    let spa_data = msg.encrypt(&keys)?;

    println!("Encrypted SPA data:");
    println!("{spa_data}");
    println!("Length: {} bytes\n", spa_data.len());

    // --- Server side: decrypt and decode ---
    let decoded = SpaMessage::decrypt(&spa_data, &keys)?;
    println!("Decrypted SPA message:");
    println!("  Username:     {}", decoded.username);
    println!("  Access:       {}", decoded.request.message_text());
    println!("  Message Type: {}", decoded.message_type());
    println!("  Timestamp:    {}", decoded.timestamp);
    println!("  Digest:       {}", decoded.digest_type);
    Ok(())
}
