//! Request NAT access: the server lets 192.168.1.50 connect on tcp/22 and
//! forwards the connection to internal host 10.0.0.100 port 22.
//!
//! Run with `cargo run -p fkospa --example nat_access`.

use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage};

fn main() -> Result<(), fkospa::Error> {
    let keys = KeySet::new(
        EncryptionKey::new("my_encryption_key"),
        EncryptionMode::Cbc,
        Some(HmacKey::new("my_hmac_key", HmacType::Sha256)),
    );

    let mut msg = SpaMessage::new(Request::NatAccess {
        access: "192.168.1.50,tcp/22".parse()?,
        nat_access: "10.0.0.100,22".into(),
        client_timeout: None,
    })?;
    msg.username = "alice".into();
    let spa_data = msg.encrypt(&keys)?;

    let decoded = SpaMessage::decrypt(&spa_data, &keys)?;
    println!("Message Type: {}", decoded.message_type());
    println!("Access:       {}", decoded.request.message_text());
    println!(
        "NAT Access:   {}",
        decoded.request.nat_access().unwrap_or("")
    );
    Ok(())
}
