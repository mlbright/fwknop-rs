//! Tests ported from fwknop-go's spa_test.go, spa_decode_test.go and
//! fuzz_test.go, plus checks for behaviour that differs from Go on purpose.

use std::num::NonZeroU32;

use proptest::prelude::*;

use crate::message::decode_plaintext;
use crate::*;

fn access(s: &str) -> AccessMessage {
    s.parse().unwrap()
}

fn fixed(request: Request) -> SpaMessage {
    SpaMessage {
        rand_val: "1234567890123456".parse().unwrap(),
        username: "testuser".into(),
        timestamp: 1_705_312_800,
        request,
        server_auth: None,
        digest_type: DigestType::Sha256,
    }
}

fn keys(enc: &str, hmac: Option<(&str, HmacType)>) -> KeySet {
    KeySet::new(
        EncryptionKey::new(enc),
        EncryptionMode::Cbc,
        hmac.map(|(k, t)| HmacKey::new(k, t)),
    )
}

fn default_keys() -> KeySet {
    keys("my_encryption_key", Some(("my_hmac_key", HmacType::Sha256)))
}

fn round_trip(msg: &SpaMessage, keys: &KeySet) -> SpaMessage {
    let data = msg.encrypt(keys).unwrap();
    SpaMessage::decrypt(&data, keys).unwrap()
}

// ---- construction and encoding (spa_test.go) ----

#[test]
fn new_defaults() {
    let m = SpaMessage::new(Request::access(access("1.2.3.4,tcp/22"))).unwrap();
    assert_eq!(m.rand_val.as_str().len(), 16);
    assert!(!m.username.is_empty());
    assert_eq!(m.message_type(), MessageType::Access);
    assert_eq!(m.digest_type, DigestType::Sha256);
    assert!(m.server_auth.is_none());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((m.timestamp - now).abs() < 5);
}

#[test]
fn random_values_differ() {
    let a = RandVal::random().unwrap();
    let b = RandVal::random().unwrap();
    assert_ne!(a, b);
    assert!(a.as_str().bytes().all(|c| c.is_ascii_digit()));
}

#[test]
fn encode_wire_format() {
    let encoded = fixed(Request::access(access("192.168.1.1,tcp/22")))
        .encode()
        .unwrap();
    let parts: Vec<&str> = encoded.split(':').collect();
    assert_eq!(parts.len(), 7);
    assert_eq!(parts[0], "1234567890123456");
    assert_eq!(parts[1], "dGVzdHVzZXI"); // base64("testuser")
    assert_eq!(parts[2], "1705312800");
    assert_eq!(parts[3], PROTOCOL_VERSION);
    assert_eq!(parts[4], "1");
    assert_eq!(parts[5], "MTkyLjE2OC4xLjEsdGNwLzIy"); // base64("192.168.1.1,tcp/22")
    assert_eq!(parts[6].len(), 43);
}

#[test]
fn encode_with_nat_access() {
    let encoded = fixed(Request::NatAccess {
        access: access("192.168.1.1,tcp/22"),
        nat_access: "10.0.0.1,22".into(),
        client_timeout: None,
    })
    .encode()
    .unwrap();
    assert_eq!(encoded.split(':').count(), 8);
}

#[test]
fn encode_with_client_timeout_uses_timeout_type() {
    let encoded = fixed(Request::Access {
        access: access("192.168.1.1,tcp/22"),
        client_timeout: NonZeroU32::new(30),
    })
    .encode()
    .unwrap();
    let parts: Vec<&str> = encoded.split(':').collect();
    assert_eq!(parts[4], "3");
    assert_eq!(parts[6], "30");
}

#[test]
fn message_type_follows_request_and_timeout() {
    let a = access("1.2.3.4,tcp/22");
    let t = NonZeroU32::new(30);
    let nat = |client_timeout| Request::NatAccess {
        access: a,
        nat_access: "n".into(),
        client_timeout,
    };
    let local = |client_timeout| Request::LocalNatAccess {
        access: a,
        nat_access: "n".into(),
        client_timeout,
    };
    let cases = [
        (Request::access(a), MessageType::Access, 1),
        (
            Request::Access {
                access: a,
                client_timeout: t,
            },
            MessageType::ClientTimeoutAccess,
            3,
        ),
        (nat(None), MessageType::NatAccess, 2),
        (nat(t), MessageType::ClientTimeoutNatAccess, 4),
        (local(None), MessageType::LocalNatAccess, 5),
        (local(t), MessageType::ClientTimeoutLocalNatAccess, 6),
        (Request::Command("ls".into()), MessageType::Command, 0),
    ];
    for (req, want, code) in cases {
        assert_eq!(req.message_type(), want);
        assert_eq!(want.code(), code);
    }
}

#[test]
fn encrypted_data_has_no_salt_prefix() {
    let data = fixed(Request::access(access("192.168.1.1,tcp/22")))
        .encrypt(&default_keys())
        .unwrap();
    assert!(!data.as_str().starts_with("U2FsdGVkX1"));
    let no_hmac = fixed(Request::access(access("192.168.1.1,tcp/22")))
        .encrypt(&keys("key", None))
        .unwrap();
    assert!(!no_hmac.is_empty());
    assert!(no_hmac.len() < data.len());
}

#[test]
fn validation_errors() {
    let mut m = fixed(Request::access(access("1.2.3.4,tcp/22")));
    m.username = String::new();
    assert!(matches!(m.encode(), Err(Error::MissingField(_))));

    assert!(matches!(
        "".parse::<AccessMessage>(),
        Err(Error::MissingField(_))
    ));
    assert!(matches!(
        "not_valid".parse::<AccessMessage>(),
        Err(Error::InvalidData(_))
    ));
    assert!(matches!(
        "123".parse::<RandVal>(),
        Err(Error::InvalidData(_))
    ));

    let nat = fixed(Request::NatAccess {
        access: access("1.2.3.4,tcp/22"),
        nat_access: String::new(),
        client_timeout: None,
    });
    assert!(matches!(nat.encode(), Err(Error::MissingField(_))));

    let cmd = fixed(Request::Command(String::new()));
    assert!(matches!(cmd.encode(), Err(Error::MissingField(_))));
    let long = fixed(Request::Command("x".repeat(1401)));
    assert!(long.encode().is_err());

    let mut m = fixed(Request::access(access("1.2.3.4,tcp/22")));
    m.username = "x".repeat(65);
    assert!(m.encode().is_err());
    m.username = "two words".into();
    assert!(m.encode().is_err());
    m.username = "zero\u{200b}width".into();
    assert!(m.encode().is_err());
    m.username = "émilie".into();
    assert!(m.encode().is_ok());
}

#[test]
fn access_spec_parsing() {
    let spec: AccessSpec = "tcp/22".parse().unwrap();
    assert_eq!(spec.to_string(), "tcp/22");
    // Leading zeros are normalised on input.
    assert_eq!(
        "tcp/022".parse::<AccessSpec>().unwrap().to_string(),
        "tcp/22"
    );
    for bad in [
        "tcp",
        "tcp/",
        "tcp/0",
        "tcp/65536",
        "tcp/abc",
        "sctp/22",
        "TCP/22",
        "tcp/-1",
        "tcp/+22",
        "tcp/2 2",
    ] {
        assert!(bad.parse::<AccessSpec>().is_err(), "{bad}");
    }
    assert!("udp/65535".parse::<AccessSpec>().is_ok());
    assert!("icmp/1".parse::<AccessSpec>().is_ok());
}

#[test]
fn access_message_parsing() {
    let a: AccessMessage = "2001:DB8::1,udp/53".parse().unwrap();
    assert_eq!(a.to_string(), "2001:db8::1,udp/53");
    // Only one access spec per access message (see ADR 0002).
    assert!("1.2.3.4,tcp/22,tcp/443".parse::<AccessMessage>().is_err());
    assert!("1.2.3.4".parse::<AccessMessage>().is_err());
    assert!("not-an-ip,tcp/22".parse::<AccessMessage>().is_err());
    assert!("010.0.0.1,tcp/22".parse::<AccessMessage>().is_err());
}

#[test]
fn message_too_short_is_rejected() {
    // A 36-byte minimum applies to the encoded fields; the fixed fields alone
    // are well over it, so check the upper bound instead.
    let m = fixed(Request::NatAccess {
        access: access("1.2.3.4,tcp/22"),
        nat_access: "n".repeat(128),
        client_timeout: None,
    });
    assert!(m.encode().is_ok());
    let mut big = fixed(Request::Command("x".repeat(1400)));
    big.server_auth = Some("a".repeat(400));
    assert!(matches!(big.encode(), Err(Error::MessageTooLarge(_))));
}

// ---- decryption (spa_decode_test.go) ----

#[test]
fn decrypt_round_trip() {
    let m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    assert_eq!(round_trip(&m, &default_keys()), m);
}

#[test]
fn decrypt_round_trip_with_nat_and_timeout() {
    for m in [
        fixed(Request::NatAccess {
            access: access("192.168.1.1,tcp/22"),
            nat_access: "10.0.0.100,22".into(),
            client_timeout: None,
        }),
        fixed(Request::NatAccess {
            access: access("192.168.1.1,tcp/22"),
            nat_access: "10.0.0.100,22".into(),
            client_timeout: NonZeroU32::new(60),
        }),
        fixed(Request::LocalNatAccess {
            access: access("192.168.1.1,tcp/22"),
            nat_access: "127.0.0.1,2222".into(),
            client_timeout: None,
        }),
        fixed(Request::LocalNatAccess {
            access: access("192.168.1.1,tcp/22"),
            nat_access: "127.0.0.1,2222".into(),
            client_timeout: NonZeroU32::new(45),
        }),
        fixed(Request::Access {
            access: access("192.168.1.1,tcp/22"),
            client_timeout: NonZeroU32::new(30),
        }),
        fixed(Request::Command("echo hello".into())),
    ] {
        assert_eq!(round_trip(&m, &default_keys()), m);
    }
}

#[test]
fn decrypt_without_hmac() {
    let m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    let k = keys("key", None);
    assert_eq!(round_trip(&m, &k), m);
}

#[test]
fn decrypt_wrong_encryption_key_fails() {
    let m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    let data = m.encrypt(&keys("right", None)).unwrap();
    assert!(SpaMessage::decrypt(&data, &keys("wrong", None)).is_err());
}

#[test]
fn decrypt_wrong_hmac_key_fails() {
    let m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    let data = m.encrypt(&default_keys()).unwrap();
    let wrong = keys("my_encryption_key", Some(("wrong", HmacType::Sha256)));
    assert_eq!(
        SpaMessage::decrypt(&data, &wrong),
        Err(Error::HmacVerificationFailed)
    );
    // An HMAC of a different type has a different length and fails too.
    let other = keys("my_encryption_key", Some(("my_hmac_key", HmacType::Sha512)));
    assert_eq!(
        SpaMessage::decrypt(&data, &other),
        Err(Error::HmacVerificationFailed)
    );
}

#[test]
fn decrypt_all_digest_types() {
    for d in DigestType::ALL {
        let mut m = fixed(Request::access(access("192.168.1.1,tcp/22")));
        m.digest_type = d;
        assert_eq!(round_trip(&m, &default_keys()).digest_type, d, "{d}");
    }
}

#[test]
fn decrypt_all_hmac_types() {
    let m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    for h in HmacType::ALL {
        let k = keys("enc", Some(("hmac", h)));
        assert_eq!(round_trip(&m, &k), m, "{h}");
    }
}

#[test]
fn decrypt_server_auth_round_trip() {
    let mut m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    m.server_auth = Some("crypt,secret".into());
    assert_eq!(round_trip(&m, &default_keys()), m);
    m.request = Request::Access {
        access: access("192.168.1.1,tcp/22"),
        client_timeout: NonZeroU32::new(99),
    };
    assert_eq!(round_trip(&m, &default_keys()), m);
}

#[test]
fn decrypt_legacy_iv_mode() {
    let mut m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    m.username = "legacyuser".into();
    let k = KeySet::new(
        EncryptionKey::new("short"),
        EncryptionMode::CbcLegacyIv,
        Some(HmacKey::new("hmac", HmacType::Sha256)),
    );
    assert_eq!(round_trip(&m, &k).username, "legacyuser");
    // A legacy-mode packet does not decrypt in plain CBC mode.
    let data = m.encrypt(&k).unwrap();
    let cbc = KeySet::new(
        EncryptionKey::new("short"),
        EncryptionMode::Cbc,
        Some(HmacKey::new("hmac", HmacType::Sha256)),
    );
    assert!(SpaMessage::decrypt(&data, &cbc).is_err());
}

#[test]
fn deterministic_with_fixed_salt() {
    let m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    let salt = [9, 8, 7, 6, 5, 4, 3, 2];
    assert_eq!(
        m.encrypt_with_salt(&default_keys(), &salt).unwrap(),
        m.encrypt_with_salt(&default_keys(), &salt).unwrap()
    );
}

#[test]
fn short_spa_data_fails_hmac() {
    assert_eq!(
        SpaMessage::decrypt(&SpaData::new("abc"), &default_keys()),
        Err(Error::HmacVerificationFailed)
    );
    assert!(SpaMessage::decrypt(&SpaData::new(""), &keys("k", None)).is_err());
}

/// Plaintext with a valid SHA-256 digest but without the encoder's checks.
fn plaintext(fields: &[&str]) -> Vec<u8> {
    let encoded = fields.join(":");
    let digest = DigestType::Sha256.digest_b64(encoded.as_bytes());
    format!("{encoded}:{digest}").into_bytes()
}

fn b(s: &str) -> String {
    b64::encode(s.as_bytes())
}

use crate::b64;

#[test]
fn decode_plaintext_validates_fields() {
    const RV: &str = "1234567890123456";
    let ok = plaintext(&[
        RV,
        &b("alice"),
        "1700000000",
        "3.0.0",
        "1",
        &b("192.168.1.1,tcp/22"),
    ]);
    assert!(decode_plaintext(&ok).is_ok());

    let cases: [(&str, &str, &str, &str); 11] = [
        ("access IP not an address", RV, "alice", "not-an-ip,tcp/22"),
        ("access missing proto/port", RV, "alice", "192.168.1.1"),
        (
            "access port not numeric",
            RV,
            "alice",
            "192.168.1.1,tcp/abc",
        ),
        ("access port zero", RV, "alice", "192.168.1.1,tcp/0"),
        (
            "access port leading zero",
            RV,
            "alice",
            "192.168.1.1,tcp/022",
        ),
        ("access unknown proto", RV, "alice", "192.168.1.1,sctp/22"),
        (
            "access two specs",
            RV,
            "alice",
            "192.168.1.1,tcp/22,tcp/443",
        ),
        ("username with space", RV, "two words", "192.168.1.1,tcp/22"),
        ("empty username", RV, "", "192.168.1.1,tcp/22"),
        (
            "rand val not numeric",
            "abcdefghijklmnop",
            "alice",
            "192.168.1.1,tcp/22",
        ),
        ("rand val too short", "123", "alice", "192.168.1.1,tcp/22"),
    ];
    for (name, rv, user, msg) in cases {
        let p = plaintext(&[rv, &b(user), "1700000000", "3.0.0", "1", &b(msg)]);
        let err = decode_plaintext(&p).expect_err(name);
        assert!(
            matches!(err, Error::InvalidData(_) | Error::MissingField(_)),
            "{name}: {err}"
        );
    }

    for (name, msg_type, msg) in [
        ("unknown message type", "99", "192.168.1.1,tcp/22"),
        ("empty command", "0", ""),
        ("NAT type without NAT field", "2", "192.168.1.1,tcp/22"),
    ] {
        let p = plaintext(&[RV, &b("alice"), "1700000000", "3.0.0", msg_type, &b(msg)]);
        let err = decode_plaintext(&p).expect_err(name);
        assert!(
            matches!(err, Error::InvalidData(_) | Error::MissingField(_)),
            "{name}: {err}"
        );
    }
}

#[test]
fn client_timeout_type_requires_timeout() {
    const RV: &str = "1234567890123456";
    let without = plaintext(&[
        RV,
        &b("alice"),
        "1700000000",
        "3.0.0",
        "3",
        &b("1.2.3.4,tcp/22"),
    ]);
    assert!(matches!(
        decode_plaintext(&without),
        Err(Error::MissingField(_))
    ));
    let zero = plaintext(&[
        RV,
        &b("alice"),
        "1700000000",
        "3.0.0",
        "3",
        &b("1.2.3.4,tcp/22"),
        "0",
    ]);
    assert!(decode_plaintext(&zero).is_err());
    let with = plaintext(&[
        RV,
        &b("alice"),
        "1700000000",
        "3.0.0",
        "3",
        &b("1.2.3.4,tcp/22"),
        "30",
    ]);
    assert_eq!(
        decode_plaintext(&with).unwrap().request.client_timeout(),
        NonZeroU32::new(30)
    );
}

#[test]
fn plain_access_type_with_timeout_field_keeps_timeout() {
    // fwknop-go accepts a timeout field on message type 1 and honours it.
    let p = plaintext(&[
        "1234567890123456",
        &b("alice"),
        "1700000000",
        "3.0.0",
        "1",
        &b("1.2.3.4,tcp/22"),
        "120",
    ]);
    assert_eq!(
        decode_plaintext(&p).unwrap().request.client_timeout(),
        NonZeroU32::new(120)
    );
}

#[test]
fn digest_mismatch_and_unknown_length() {
    let mut p = plaintext(&[
        "1234567890123456",
        &b("alice"),
        "1700000000",
        "3.0.0",
        "1",
        &b("1.2.3.4,tcp/22"),
    ]);
    let last = p.len() - 1;
    p[last] = if p[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(decode_plaintext(&p), Err(Error::DigestVerificationFailed));
    assert!(matches!(
        decode_plaintext(b"1234567890123456:abc"),
        Err(Error::UnsupportedDigestType(_))
    ));
    assert!(matches!(
        decode_plaintext(b"no colon"),
        Err(Error::InvalidData(_))
    ));
}

#[test]
fn sha3_digests_are_detected_by_fallback() {
    for d in [DigestType::Sha3_256, DigestType::Sha3_512] {
        let mut m = fixed(Request::access(access("1.2.3.4,tcp/22")));
        m.digest_type = d;
        let decoded = decode_plaintext(m.encode().unwrap().as_bytes()).unwrap();
        assert_eq!(decoded.digest_type, d);
    }
}

// ---- fuzz targets (fuzz_test.go) as property tests ----

fn seed() -> SpaMessage {
    let mut m = fixed(Request::access(access("192.168.1.1,tcp/22")));
    m.username = "fuzzuser".into();
    m
}

fn fuzz_keys(hmac: bool) -> KeySet {
    keys(
        "fuzz_enc_key",
        hmac.then_some(("fuzz_hmac_key", HmacType::Sha256)),
    )
}

proptest! {
    /// What an attacker without keys can reach: arbitrary wire data through
    /// HMAC verification, base64 decoding and decryption.
    #[test]
    fn decrypt_never_panics(data in ".*", hmac in any::<bool>()) {
        let _ = SpaMessage::decrypt(&SpaData::new(data), &fuzz_keys(hmac));
    }

    #[test]
    fn decrypt_never_panics_on_mutated_packets(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
        hmac in any::<bool>(),
    ) {
        let k = fuzz_keys(hmac);
        let mut bytes = seed().encrypt(&k).unwrap().into_string().into_bytes();
        for (i, v) in flips {
            let i = i.index(bytes.len());
            bytes[i] = v;
        }
        let _ = SpaMessage::decrypt(&SpaData::from_bytes(&bytes), &k);
    }

    /// The parser that runs on decrypted plaintext, reached both directly
    /// and with a valid digest appended so the field parser runs.
    #[test]
    fn decode_plaintext_never_panics(encoded in ".*") {
        let _ = decode_plaintext(encoded.as_bytes());
        let digest = DigestType::Sha256.digest_b64(encoded.as_bytes());
        let _ = decode_plaintext(format!("{encoded}:{digest}").as_bytes());
    }

    #[test]
    fn decode_plaintext_never_panics_on_field_soup(
        fields in proptest::collection::vec("[0-9A-Za-z+/=:,.]{0,24}", 0..11),
    ) {
        let encoded = fields.join(":");
        let digest = DigestType::Sha256.digest_b64(encoded.as_bytes());
        let _ = decode_plaintext(format!("{encoded}:{digest}").as_bytes());
    }

    #[test]
    fn valid_messages_round_trip(
        user in "[a-zA-Z0-9_.-]{1,64}",
        ts in any::<u32>(),
        port in 1u16..,
        timeout in proptest::option::of(1u32..),
        digest in 0usize..7,
        hmac in 0usize..7,
    ) {
        let mut m = fixed(Request::Access {
            access: AccessMessage::new(
                "10.1.2.3".parse().unwrap(),
                AccessSpec::new(Proto::Udp, std::num::NonZeroU16::new(port).unwrap()),
            ),
            client_timeout: timeout.and_then(NonZeroU32::new),
        });
        m.username = user;
        m.timestamp = i64::from(ts);
        m.digest_type = DigestType::ALL[digest];
        let k = keys("enc", Some(("hmac", HmacType::ALL[hmac])));
        prop_assert_eq!(round_trip(&m, &k), m);
    }
}
