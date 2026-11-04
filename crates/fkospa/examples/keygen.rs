//! Generate random encryption and HMAC keys.
//!
//! Run with `cargo run -p fkospa --example keygen`.

fn main() -> Result<(), fkospa::Error> {
    // 32 bytes (256 bits) each.
    let enc_key = fkospa::generate_key(32)?;
    let hmac_key = fkospa::generate_key(32)?;

    println!("Add these to your client .fwknoprc and server access.yaml:");
    println!();
    println!("KEY_BASE64:      {enc_key}");
    println!("HMAC_KEY_BASE64: {hmac_key}");
    Ok(())
}
