//! Cross-checks against the C library (libfko).
//!
//! `testdata/golden_vectors.txt` was produced by `testdata/gen_golden.c`
//! from fixed inputs and is shared unchanged with fwknop-go. Each vector
//! gives the inputs, the encoded plaintext and digest C produced, and the
//! encrypted SPA data C produced.

use std::num::NonZeroU32;

use fkospa::{
    DigestType, EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaData,
    SpaMessage,
};

#[derive(Debug, Default)]
struct Vector {
    name: String,
    rand_val: String,
    username: String,
    timestamp: i64,
    msg_type: u8,
    access_msg: String,
    nat_access: String,
    server_auth: String,
    client_timeout: u32,
    digest_type: usize,
    enc_mode: u8,
    hmac_type: usize,
    enc_key: String,
    hmac_key: String,
    encoded_data: String,
    digest: String,
    spa_data: String,
}

fn vectors() -> Vec<Vector> {
    let text = include_str!("testdata/golden_vectors.txt");
    let mut out: Vec<Vector> = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(name) = line
            .strip_prefix("--- ")
            .and_then(|l| l.strip_suffix(" ---"))
        {
            out.push(Vector {
                name: name.to_string(),
                ..Vector::default()
            });
            continue;
        }
        let (Some(v), Some((key, val))) = (out.last_mut(), line.split_once('=')) else {
            continue;
        };
        let val = val.to_string();
        match key {
            "rand_val" => v.rand_val = val,
            "username" => v.username = val,
            "timestamp" => v.timestamp = val.parse().unwrap(),
            "msg_type" => v.msg_type = val.parse().unwrap(),
            "access_msg" => v.access_msg = val,
            "nat_access" => v.nat_access = val,
            "server_auth" => v.server_auth = val,
            "client_timeout" => v.client_timeout = val.parse().unwrap(),
            "digest_type" => v.digest_type = val.parse().unwrap(),
            "enc_mode" => v.enc_mode = val.parse().unwrap(),
            "hmac_type" => v.hmac_type = val.parse().unwrap(),
            "enc_key" => v.enc_key = val,
            "hmac_key" => v.hmac_key = val,
            "encoded_data" => v.encoded_data = val,
            "digest" => v.digest = val,
            "spa_data" => v.spa_data = val,
            _ => {}
        }
    }
    assert_eq!(out.len(), 8, "expected 8 golden vectors");
    out
}

impl Vector {
    /// The C library's SHA-1 is non-standard on macOS (a byte-order bug), so
    /// its SHA-1 vectors cannot be matched by a correct implementation.
    fn is_sha1(&self) -> bool {
        self.digest_type == 2
    }

    fn message(&self) -> SpaMessage {
        let access = self.access_msg.parse().unwrap();
        let client_timeout = NonZeroU32::new(self.client_timeout);
        let nat_access = self.nat_access.clone();
        // C's message types; the client-timeout variants come from the
        // timeout, as in fwknop.
        let request = match self.msg_type {
            1 | 3 => Request::Access {
                access,
                client_timeout,
            },
            2 | 4 => Request::NatAccess {
                access,
                nat_access,
                client_timeout,
            },
            5 | 6 => Request::LocalNatAccess {
                access,
                nat_access,
                client_timeout,
            },
            other => panic!("{}: unexpected message type {other}", self.name),
        };
        SpaMessage {
            rand_val: self.rand_val.parse().unwrap(),
            username: self.username.clone(),
            timestamp: self.timestamp,
            request,
            server_auth: (!self.server_auth.is_empty()).then(|| self.server_auth.clone()),
            digest_type: DigestType::ALL[self.digest_type - 1],
        }
    }

    fn keys(&self) -> KeySet {
        let mode = match self.enc_mode {
            2 => EncryptionMode::Cbc,
            8 => EncryptionMode::CbcLegacyIv,
            other => panic!("{}: unexpected encryption mode {other}", self.name),
        };
        let hmac = (!self.hmac_key.is_empty())
            .then(|| HmacKey::new(self.hmac_key.as_bytes(), HmacType::ALL[self.hmac_type - 1]));
        KeySet::new(EncryptionKey::new(self.enc_key.as_bytes()), mode, hmac)
    }
}

/// Encoding must be byte-identical to C's `fko_encode_spa_data()`.
#[test]
fn golden_encoding() {
    let mut checked = 0;
    for v in vectors().iter().filter(|v| !v.is_sha1()) {
        let encoded = v.message().encode().unwrap();
        assert_eq!(
            encoded,
            format!("{}:{}", v.encoded_data, v.digest),
            "{}",
            v.name
        );
        checked += 1;
    }
    assert_eq!(checked, 7);
}

/// SPA data encrypted by C decrypts to the original fields.
#[test]
fn golden_decrypt() {
    for v in vectors().iter().filter(|v| !v.is_sha1()) {
        let decoded = SpaMessage::decrypt(&SpaData::new(v.spa_data.clone()), &v.keys())
            .unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(decoded, v.message(), "{}", v.name);
    }
}

/// Every vector, SHA-1 included, survives a Rust encrypt/decrypt round trip.
#[test]
fn golden_cross_encrypt_decrypt() {
    for v in vectors() {
        let keys = v.keys();
        let msg = v.message();
        let decoded = SpaMessage::decrypt(&msg.encrypt(&keys).unwrap(), &keys).unwrap();
        assert_eq!(decoded, msg, "{}", v.name);
    }
}

/// C data must not decrypt under the wrong keys.
#[test]
fn golden_rejects_wrong_keys() {
    for v in vectors().iter().filter(|v| !v.is_sha1()) {
        let mut keys = v.keys();
        keys.encryption_key = EncryptionKey::new("not the key");
        assert!(
            SpaMessage::decrypt(&SpaData::new(v.spa_data.clone()), &keys).is_err(),
            "{}",
            v.name
        );
    }
}
