# fkospa developer guide

The fkospa crate implements the fwknop Single Packet Authorization (SPA)
protocol in Rust.

**Protocol**: 3.0.0, compatible with C fwknop and fwknop-go.

## Contents

1. [Introduction](#introduction)
2. [Getting started](#getting-started)
3. [The SPA message](#the-spa-message)
4. [Algorithms](#algorithms)
5. [Building SPA messages](#building-spa-messages)
6. [Encrypting](#encrypting)
7. [Decrypting and decoding](#decrypting-and-decoding)
8. [Advanced topics](#advanced-topics)
9. [Errors](#errors)
10. [API summary](#api-summary)
11. [Compatibility](#compatibility)

---

## Introduction

SPA lets a client ask a server to open firewall access with a single UDP
packet that is encrypted, authenticated with an HMAC and impossible to
replay. Until such a packet arrives, the server's firewall drops everything,
so services behind it (such as SSH) cannot even be found with a port scan.

fkospa is not a client or a server. It builds, encrypts, decrypts and
decodes the SPA data those programs exchange. The `fwknop` client and the
`fwknopd` server in fwknop-rs use it, and the `fwknop` crate wraps it to send
a knock in one call. It does no networking itself.

Features:

- **The whole protocol**: build, encrypt, authenticate, decrypt, decode and
  verify SPA messages.
- **Seven hash algorithms**: MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256 and
  SHA3-512, for both message digests and HMACs.
- **AES-256-CBC**, with OpenSSL's `EVP_BytesToKey` key derivation, and the
  legacy IV key padding older clients used.
- **All seven message types**: access, NAT access, local NAT access, server
  command, and the client-timeout variants.
- **Invalid messages cannot be built**: a [`Request`] carries an access
  message or a server command, with NAT access and a client timeout only
  where the message type allows them.
- **Keys are wiped**: [`EncryptionKey`] and [`HmacKey`] zero their bytes when
  dropped and never print them.

## Getting started

Add the crate (it is not on crates.io yet):

```toml
[dependencies]
fkospa = { git = "https://github.com/mlbright/fwknop-rs" }
```

A first message:

```rust
use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage};

// Ask for SSH access for 192.168.1.50.
let msg = SpaMessage::new(Request::access("192.168.1.50,tcp/22".parse()?))?;

let keys = KeySet::new(
    EncryptionKey::new("encryption_key"),
    EncryptionMode::Cbc,
    Some(HmacKey::new("hmac_key", HmacType::Sha256)),
);
let spa_data = msg.encrypt(&keys)?;

// spa_data is the payload to send in one UDP datagram.
println!("SPA data length: {}", spa_data.len());
# Ok::<(), fkospa::Error>(())
```

---

## The SPA message

Before encryption, an SPA message is a colon-separated string, with some
fields base64-encoded (standard alphabet, `=` padding removed):

```text
RAND_VAL : B64(USERNAME) : TIMESTAMP : VERSION : MSG_TYPE : B64(MESSAGE) [: B64(NAT_ACCESS)] [: B64(SERVER_AUTH)] [: CLIENT_TIMEOUT] : DIGEST
```

[`SpaMessage`] holds the decoded fields:

| Field | Type | Default from `SpaMessage::new` | Meaning |
|-------|------|------------------------------|---------|
| `rand_val` | [`RandVal`] | 16 random digits | Makes every packet unique |
| `username` | `String` | The current user | Who is asking; servers can require one |
| `timestamp` | `i64` | Now (Unix seconds) | Lets the server reject old packets |
| `request` | [`Request`] | (you choose) | What is asked for; decides `MSG_TYPE`, `MESSAGE`, `NAT_ACCESS` and `CLIENT_TIMEOUT` |
| `server_auth` | `Option<String>` | `None` | Optional server authentication string |
| `digest_type` | [`DigestType`] | `Sha256` | The message digest's hash |

`VERSION` is always [`PROTOCOL_VERSION`] (`3.0.0`). The message type number
is not stored: [`SpaMessage::message_type`] works it out from the request.

A fully populated example:

```text
8307540982176539:anVzZXI:1230665172:3.0.0:4:MTkyLjE2OC4xLjEsdGNwLzIy:MTAuMC4wLjEsMjI:Y3J5cHQsbXlwdw:120:xswj8V0zMR7/7MV9pQRarSKWG1l9Zfjv+kbXaKrJ+RA
```

That is a random value, base64("juser"), a timestamp, the version, message
type 4 (NAT access with a client timeout), base64("192.168.1.1,tcp/22"),
base64 NAT access, base64 server auth, a 120-second timeout and a SHA-256
digest.

### Requests

| `Request` variant | Message type | Carries |
|-------------------|--------------|---------|
| `Command(String)` | 0 `Command` | A server command, e.g. `uname -a` |
| `Access { access, client_timeout: None }` | 1 `Access` | An access message |
| `NatAccess { access, nat_access, client_timeout: None }` | 2 `NATAccess` | An access message and NAT access (`internal_ip,port`) |
| `Access { access, client_timeout: Some(t) }` | 3 `ClientTimeoutAccess` | …and a client timeout |
| `NatAccess { .., client_timeout: Some(t) }` | 4 `ClientTimeoutNATAccess` | |
| `LocalNatAccess { access, nat_access, client_timeout: None }` | 5 `LocalNATAccess` | NAT to a service on the server itself |
| `LocalNatAccess { .., client_timeout: Some(t) }` | 6 `ClientTimeoutLocalNATAccess` | |

An [`AccessMessage`] is an allow IP and one [`AccessSpec`]
(`proto/port`, with `proto` one of `tcp`, `udp`, `icmp`), written
`allow_ip,proto/port`:

```rust
use fkospa::{AccessMessage, Proto};

let access: AccessMessage = "192.168.1.2,tcp/22".parse()?;
assert_eq!(access.spec.proto, Proto::Tcp);
assert_eq!(access.spec.port.get(), 22);

// One access spec per access message.
assert!("192.168.1.2,tcp/22,udp/53".parse::<AccessMessage>().is_err());
# Ok::<(), fkospa::Error>(())
```

An allow IP of `0.0.0.0` (or `::`) asks the server to open access for
whatever address the packet arrives from.

---

## Algorithms

### Digest types

The message digest is a hash of the encoded fields, appended before
encryption. The server recognises the algorithm from the digest's length,
trying SHA3-256 after SHA-256 and SHA3-512 after SHA-512, since those pairs
have the same length.

| `DigestType` | Name in flags and config |
|--------------|--------------------------|
| `Md5` | `md5` |
| `Sha1` | `sha1` |
| `Sha256` (default) | `sha256` |
| `Sha384` | `sha384` |
| `Sha512` | `sha512` |
| `Sha3_256` | `sha3_256` or `sha3-256` |
| `Sha3_512` | `sha3_512` or `sha3-512` |

`DigestType`, `HmacType` and `EncryptionMode` all implement `FromStr` for
these names (ignoring case) and `Display` for fwknop's labels (`SHA256`,
`HMAC-SHA256`, `CBC`).

### HMAC types

[`HmacType`] has the same seven variants. The HMAC is computed over the
encrypted SPA data, so the server must be configured with the same HMAC type
(there is no length trick here); it is part of the [`KeySet`].

### Encryption modes

| `EncryptionMode` | Name | Meaning |
|------------------|------|---------|
| `Cbc` (default) | `cbc` | AES-256-CBC, key and IV from `EVP_BytesToKey` (MD5) |
| `CbcLegacyIv` | `legacy` | The same, with encryption keys shorter than 16 bytes padded with `'0'` first, as old clients did |

The mode is not on the wire either, so it is also part of the key set.

---

## Building SPA messages

[`SpaMessage::new`] fills in the defaults. The fields are public, so change
whatever you need directly:

```rust
use std::num::NonZeroU32;
use fkospa::{DigestType, Request, SpaMessage};

let mut msg = SpaMessage::new(Request::Access {
    access: "10.0.0.1,tcp/22".parse()?,
    client_timeout: NonZeroU32::new(60),
})?;
msg.username = "alice".into();
msg.digest_type = DigestType::Sha512;
msg.timestamp -= 30; // pretend it was built 30 seconds ago
# Ok::<(), fkospa::Error>(())
```

Field values are checked when the message is encoded:

- The username must be 1–64 bytes of printable characters with no spaces.
- A server command must be 1–1400 bytes.
- NAT access must be 1–128 bytes.
- The encoded message must be 36–1500 bytes.

[`SpaMessage::encode`] shows the plaintext that will be encrypted, which is
handy for debugging:

```rust
use fkospa::{Request, SpaMessage};

let mut msg = SpaMessage::new(Request::access("192.168.1.1,tcp/22".parse()?))?;
msg.rand_val = "1234567890123456".parse()?;
msg.username = "alice".into();
msg.timestamp = 1_700_000_000;
assert_eq!(
    msg.encode()?,
    "1234567890123456:YWxpY2U:1700000000:3.0.0:1:MTkyLjE2OC4xLjEsdGNwLzIy:\
     InhdiYP3+F4uF1ShX9rkUs/lL8N86cJPn4VWjmXpU1w"
);
# Ok::<(), fkospa::Error>(())
```

---

## Encrypting

A [`KeySet`] holds what client and server must share: the encryption key,
the encryption mode, and optionally an HMAC key with its HMAC type.

```rust
use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage};

let keys = KeySet::new(
    EncryptionKey::from_base64("bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=")?,
    EncryptionMode::Cbc,
    Some(HmacKey::from_base64("ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=", HmacType::Sha256)?),
);
let msg = SpaMessage::new(Request::access("203.0.113.7,tcp/22".parse()?))?;
let spa_data = msg.encrypt(&keys)?;
# Ok::<(), fkospa::Error>(())
```

What `encrypt` does:

1. **Encode**: the fields plus the message digest, as above.
2. **Encrypt**: AES-256-CBC with PKCS#7 padding and a random 8-byte salt, in
   OpenSSL's format: `"Salted__" || salt || ciphertext`.
3. **Base64**: encode the ciphertext, without `=` padding.
4. **Strip the prefix**: every result starts with `U2FsdGVkX1` (base64 of
   `Salted__`), so that constant is dropped from the wire.
5. **HMAC**: when the key set has an HMAC key, compute the HMAC over the
   base64 *with* the prefix and append it, base64-encoded.

With `hmac: None`, step 5 is skipped. The server must then also have no HMAC
key for that access stanza.

---

## Decrypting and decoding

```rust
use fkospa::{EncryptionKey, EncryptionMode, KeySet, MessageType, Request, SpaData, SpaMessage};

let keys = KeySet::new(EncryptionKey::new("shared_secret"), EncryptionMode::Cbc, None);
# let sent = SpaMessage::new(Request::access("192.168.1.50,tcp/22".parse()?))?;
# let wire: String = sent.encrypt(&keys)?.into_string();
// `wire` is the payload of a received datagram.
let msg = SpaMessage::decrypt(&SpaData::new(wire), &keys)?;
assert_eq!(msg.message_type(), MessageType::Access);
assert_eq!(msg.request.message_text(), "192.168.1.50,tcp/22");
# Ok::<(), fkospa::Error>(())
```

`SpaData::from_bytes` builds SPA data straight from a datagram's bytes.

What `decrypt` does:

1. **HMAC**: with an HMAC key, split the HMAC off the end (its length comes
   from the HMAC type), recompute it over the prefix plus the rest, and
   compare in constant time.
2. **Base64-decode** the ciphertext with the prefix restored.
3. **Decrypt** with the key set's mode. As in C fwknop, invalid padding is
   not an error by itself; the digest check catches a wrong key.
4. **Verify the message digest**, detecting its algorithm from its length.
5. **Decode and check every field** the way `encode` does. The digest proves
   the plaintext is intact, not that a well-behaved client produced it, and
   servers substitute these fields into commands.

Two decoding rules differ from fwknop-go:

- A client-timeout message type without a timeout field is rejected.
- A port with leading zeros (`tcp/022`) is rejected, as fwknop-go's server
  already did. When you parse user input with `"tcp/022".parse()`, leading
  zeros are accepted and dropped.

---

## Advanced topics

### NAT access

```rust
use fkospa::{Request, SpaMessage};

let msg = SpaMessage::new(Request::NatAccess {
    access: "203.0.113.50,tcp/22".parse()?,
    nat_access: "10.0.1.100,22".into(), // internal_ip,port
    client_timeout: None,
})?;
assert_eq!(msg.request.nat_access(), Some("10.0.1.100,22"));
# Ok::<(), fkospa::Error>(())
```

For a service on the server itself, use `Request::LocalNatAccess` with
something like `"127.0.0.1,8080"`.

### Server commands

```rust
use fkospa::{MessageType, Request, SpaMessage};

let msg = SpaMessage::new(Request::Command("uname -a".into()))?;
assert_eq!(msg.message_type(), MessageType::Command);
# Ok::<(), fkospa::Error>(())
```

The server runs it only if the access stanza has `enable_cmd_exec: true`.
A server command carries no allow IP and no client timeout.

### Client timeout

The client timeout asks the server to keep the rule open for that many
seconds, up to the access stanza's max access timeout. Setting it turns an
access, NAT access or local NAT access request into its client-timeout
message type:

```rust
use std::num::NonZeroU32;
use fkospa::{MessageType, Request, SpaMessage};

let msg = SpaMessage::new(Request::Access {
    access: "10.0.0.1,tcp/22".parse()?,
    client_timeout: NonZeroU32::new(60),
})?;
assert_eq!(msg.message_type(), MessageType::ClientTimeoutAccess);
# Ok::<(), fkospa::Error>(())
```

### Server auth

`server_auth` is an optional extra string carried in the message. It is
rarely used and kept for protocol completeness.

### Legacy IV mode

For old clients with short passphrases, use `EncryptionMode::CbcLegacyIv` on
both sides. Encryption keys shorter than 16 bytes are padded with `'0'`
characters before key derivation.

### Generating keys

```rust
let key = fkospa::generate_key(32)?;      // standard base64, like fwknop --key-gen
let hmac_key = fkospa::generate_key(32)?;
assert_eq!(fkospa::decode_base64_key(&key)?.len(), 32);
# let _ = hmac_key;
# Ok::<(), fkospa::Error>(())
```

### Replay digests

Servers recognise a replayed packet by a hash of its SPA data;
`DigestType::Sha256.digest_b64(data)` gives the one fwknopd uses.

---

## Errors

Every fallible function returns [`Error`], whose variants match fwknop-go's
error values:

| Variant | Meaning |
|---------|---------|
| `InvalidData` | Malformed or out-of-range input |
| `MessageTooLarge` | The encoded message is outside 36–1500 bytes |
| `MissingField` | A required field is empty |
| `DigestVerificationFailed` | The message digest does not match (wrong key or corruption) |
| `HmacVerificationFailed` | The HMAC does not match (wrong HMAC key or type, or tampering) |
| `DecryptionFailed` | The SPA data is not valid ciphertext |
| `UnsupportedEncryptionMode` | An encryption mode name other than `cbc` or `legacy` |
| `InvalidKeyLen` | A key length of zero for `generate_key` |
| `UnsupportedDigestType` | An unknown digest name, or a digest of unrecognised length |
| `UnsupportedHmacType` | An unknown HMAC name |
| `Random` | The OS random number generator failed |
| `Username` | The current user's name could not be found |

```rust
use fkospa::{EncryptionKey, EncryptionMode, Error, HmacKey, HmacType, KeySet, SpaData, SpaMessage};

let keys = KeySet::new(
    EncryptionKey::new("k"),
    EncryptionMode::Cbc,
    Some(HmacKey::new("h", HmacType::Sha256)),
);
match SpaMessage::decrypt(&SpaData::new("not really spa data"), &keys) {
    Err(Error::HmacVerificationFailed) => println!("wrong HMAC key, or tampered data"),
    Err(Error::DigestVerificationFailed) => println!("wrong encryption key, or corrupted data"),
    Err(e) => println!("SPA processing error: {e}"),
    Ok(msg) => println!("from {}", msg.username),
}
```

---

## API summary

| Item | What it is |
|------|------------|
| [`SpaMessage`] | The decoded contents of SPA data; `new`, `encode`, `encrypt`, `decrypt`, `message_type` |
| [`Request`] | What an SPA message asks for: `Command`, `Access`, `NatAccess`, `LocalNatAccess` |
| [`AccessMessage`], [`AccessSpec`], [`Proto`] | `allow_ip,proto/port` and its parts |
| [`RandVal`] | The 16-digit random value |
| [`MessageType`] | The seven message types, with their wire numbers (`code()`) |
| [`SpaData`] | The encrypted base64 string that travels on the wire |
| [`KeySet`], [`EncryptionKey`], [`HmacKey`] | Keys and modes shared by client and server |
| [`DigestType`], [`HmacType`], [`EncryptionMode`] | The algorithms |
| [`generate_key`], [`decode_base64_key`] | Key helpers |
| [`Error`] | Everything that can go wrong |
| [`PROTOCOL_VERSION`], [`VERSION`] | `3.0.0`, and the crate's version |

The crate's API docs (`cargo doc -p fkospa --open`) cover every item.

---

## Compatibility

- **C fwknop**: for the golden vectors in `crates/fkospa/tests/testdata/`
  (generated by `gen_golden.c` with libfko), encoding is byte-identical and
  libfko's SPA data decrypts. SHA-1 vectors are skipped, because the C SHA-1
  is non-standard on macOS (a byte-order bug). `EVP_BytesToKey` output and
  the AES ciphertext are also checked against OpenSSL.
- **fwknop-go**: `make interop` exchanges packets between the Rust and Go
  clients and servers for every digest, HMAC and encryption-mode
  combination.

How fkospa differs from fwknop-go's package, and why, is in
[docs/deviations-from-go.md](../docs/deviations-from-go.md).

[`SpaMessage`]: https://docs.rs/fkospa/latest/fkospa/struct.SpaMessage.html
[`SpaMessage::new`]: https://docs.rs/fkospa/latest/fkospa/struct.SpaMessage.html#method.new
[`SpaMessage::encode`]: https://docs.rs/fkospa/latest/fkospa/struct.SpaMessage.html#method.encode
[`SpaMessage::message_type`]: https://docs.rs/fkospa/latest/fkospa/struct.SpaMessage.html#method.message_type
[`Request`]: https://docs.rs/fkospa/latest/fkospa/enum.Request.html
[`AccessMessage`]: https://docs.rs/fkospa/latest/fkospa/struct.AccessMessage.html
[`AccessSpec`]: https://docs.rs/fkospa/latest/fkospa/struct.AccessSpec.html
[`Proto`]: https://docs.rs/fkospa/latest/fkospa/enum.Proto.html
[`RandVal`]: https://docs.rs/fkospa/latest/fkospa/struct.RandVal.html
[`MessageType`]: https://docs.rs/fkospa/latest/fkospa/enum.MessageType.html
[`SpaData`]: https://docs.rs/fkospa/latest/fkospa/struct.SpaData.html
[`KeySet`]: https://docs.rs/fkospa/latest/fkospa/struct.KeySet.html
[`EncryptionKey`]: https://docs.rs/fkospa/latest/fkospa/struct.EncryptionKey.html
[`HmacKey`]: https://docs.rs/fkospa/latest/fkospa/struct.HmacKey.html
[`DigestType`]: https://docs.rs/fkospa/latest/fkospa/enum.DigestType.html
[`HmacType`]: https://docs.rs/fkospa/latest/fkospa/enum.HmacType.html
[`EncryptionMode`]: https://docs.rs/fkospa/latest/fkospa/enum.EncryptionMode.html
[`generate_key`]: https://docs.rs/fkospa/latest/fkospa/fn.generate_key.html
[`decode_base64_key`]: https://docs.rs/fkospa/latest/fkospa/fn.decode_base64_key.html
[`Error`]: https://docs.rs/fkospa/latest/fkospa/enum.Error.html
[`PROTOCOL_VERSION`]: https://docs.rs/fkospa/latest/fkospa/constant.PROTOCOL_VERSION.html
[`VERSION`]: https://docs.rs/fkospa/latest/fkospa/constant.VERSION.html
