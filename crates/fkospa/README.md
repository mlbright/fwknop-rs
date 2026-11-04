# fkospa

The [fwknop](https://www.cipherdyne.org/fwknop/) Single Packet Authorization
(SPA) protocol in Rust: build, encrypt, decrypt and decode SPA messages
compatible with C fwknop and fwknop-go (protocol 3.0.0).

```rust
use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage};

let keys = KeySet::new(
    EncryptionKey::new("encryption key"),
    EncryptionMode::Cbc,
    Some(HmacKey::new("hmac key", HmacType::Sha256)),
);

// Client side
let msg = SpaMessage::new(Request::access("203.0.113.7,tcp/22".parse()?))?;
let spa_data = msg.encrypt(&keys)?;

// Server side
let received = SpaMessage::decrypt(&spa_data, &keys)?;
assert_eq!(received, msg);
# Ok::<(), fkospa::Error>(())
```

To send a knock over the network, use the `fwknop` crate. Part of
[fwknop-rs](https://github.com/mlbright/fwknop-rs); licensed under the GPL
v2.
