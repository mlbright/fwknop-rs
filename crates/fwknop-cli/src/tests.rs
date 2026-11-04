//! Tests ported from fwknop-go's cmd/fwknop/main_test.go, checking the SPA
//! data the client prints in test mode as well as that it runs.

use std::net::UdpSocket;
use std::num::NonZeroU32;
use std::time::Duration;

use clap::Parser;
use fkospa::{
    DigestType, EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, MessageType, Request,
    SpaData, SpaMessage,
};

use super::*;

const BASE: &[&str] = &[
    "--destination",
    "127.0.0.1",
    "--access",
    "tcp/22",
    "--allow-ip",
    "10.0.0.1",
    "--key",
    "test_encryption_key",
    "--key-hmac",
    "test_hmac_key",
    "--no-rc-file",
];

#[derive(Debug)]
struct Output {
    out: String,
    err: String,
}

fn run_args(args: &[&str]) -> Result<Output> {
    let cli = Cli::try_parse_from(std::iter::once("fwknop").chain(args.iter().copied()))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    run(&cli, [("", ""); 0], &mut out, &mut err)?;
    Ok(Output {
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    })
}

/// Runs in test mode with `extra` flags after [`BASE`] and decrypts the
/// printed SPA data.
fn test_mode(extra: &[&str], keys: &KeySet) -> SpaMessage {
    let mut args = BASE.to_vec();
    args.push("--test");
    args.extend_from_slice(extra);
    let output = run_args(&args).unwrap();
    let data = SpaData::new(output.out.trim_end());
    SpaMessage::decrypt(&data, keys).unwrap()
}

fn base_keys() -> KeySet {
    KeySet::new(
        EncryptionKey::new("test_encryption_key"),
        EncryptionMode::Cbc,
        Some(HmacKey::new("test_hmac_key", HmacType::Sha256)),
    )
}

#[test]
fn key_gen() {
    let out = run_args(&["--key-gen"]).unwrap().out;
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("KEY_BASE64: "));
    assert!(lines[1].starts_with("HMAC_KEY_BASE64: "));
    let key = lines[0].trim_start_matches("KEY_BASE64: ");
    assert_eq!(fkospa::decode_base64_key(key).unwrap().len(), 32);
}

#[test]
fn version() {
    let out = run_args(&["-V"]).unwrap().out;
    assert!(out.starts_with("fwknop (Rust) version 0.1.0"), "{out}");
    assert!(out.trim_end().ends_with("(SPA protocol 3.0.0)"), "{out}");
}

#[test]
fn test_mode_builds_an_access_request() {
    let msg = test_mode(&[], &base_keys());
    assert_eq!(msg.request.message_text(), "10.0.0.1,tcp/22");
    assert_eq!(msg.message_type(), MessageType::Access);
    assert_eq!(msg.digest_type, DigestType::Sha256);
}

#[test]
fn test_mode_with_digest_types() {
    for d in [
        "md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-512",
    ] {
        let msg = test_mode(&["--digest-type", d], &base_keys());
        assert_eq!(msg.digest_type, d.parse().unwrap(), "{d}");
    }
}

#[test]
fn test_mode_with_hmac_types() {
    for h in HmacType::ALL {
        let name = h.to_string().trim_start_matches("HMAC-").to_lowercase();
        let mut keys = base_keys();
        keys.hmac = Some(HmacKey::new("test_hmac_key", h));
        test_mode(&["--hmac-digest-type", &name], &keys);
    }
}

#[test]
fn test_mode_with_legacy_encryption() {
    let mut keys = base_keys();
    keys.encryption_mode = EncryptionMode::CbcLegacyIv;
    test_mode(&["--encryption-mode", "legacy"], &keys);
}

#[test]
fn test_mode_without_hmac() {
    let mut keys = base_keys();
    keys.hmac = None;
    test_mode(&["--use-hmac=false"], &keys);
}

#[test]
fn test_mode_with_base64_keys() {
    let keys = KeySet::new(
        EncryptionKey::new("testkey"),
        EncryptionMode::Cbc,
        Some(HmacKey::new("hmackey", HmacType::Sha256)),
    );
    let mut args = BASE[..6].to_vec();
    args.extend_from_slice(&[
        "--key-base64",
        "dGVzdGtleQ==",
        "--key-base64-hmac",
        "aG1hY2tleQ==",
        "--no-rc-file",
        "-T",
    ]);
    let out = run_args(&args).unwrap().out;
    SpaMessage::decrypt(&SpaData::new(out.trim_end()), &keys).unwrap();
}

#[test]
fn test_mode_with_timeout() {
    let msg = test_mode(&["--fw-timeout", "60"], &base_keys());
    assert_eq!(msg.message_type(), MessageType::ClientTimeoutAccess);
    assert_eq!(msg.request.client_timeout(), NonZeroU32::new(60));
}

#[test]
fn test_mode_with_nat_access() {
    let msg = test_mode(&["--nat-access", "192.168.1.100,22"], &base_keys());
    assert_eq!(msg.message_type(), MessageType::NatAccess);
    assert_eq!(msg.request.nat_access(), Some("192.168.1.100,22"));

    let msg = test_mode(
        &["--nat-access", "127.0.0.1,2222", "--nat-local", "-f", "30"],
        &base_keys(),
    );
    assert_eq!(msg.message_type(), MessageType::ClientTimeoutLocalNatAccess);
}

#[test]
fn test_mode_with_server_cmd() {
    let args = [
        "--destination",
        "127.0.0.1",
        "--server-cmd",
        "echo hello",
        "--allow-ip",
        "10.0.0.1",
        "--key",
        "test_encryption_key",
        "--key-hmac",
        "test_hmac_key",
        "--test",
        "--no-rc-file",
    ];
    let out = run_args(&args).unwrap().out;
    let msg = SpaMessage::decrypt(&SpaData::new(out.trim_end()), &base_keys()).unwrap();
    assert_eq!(msg.request, Request::Command("echo hello".into()));
}

#[test]
fn server_cmd_needs_no_allow_ip() {
    let args = [
        "-D",
        "127.0.0.1",
        "-C",
        "uptime",
        "--key",
        "k",
        "--key-hmac",
        "h",
        "-T",
        "--no-rc-file",
    ];
    assert!(run_args(&args).is_ok());
}

#[test]
fn test_mode_with_time_offset() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let msg = test_mode(&["--time-offset-plus", "2m"], &base_keys());
    assert!((msg.timestamp - (now + 120)).abs() <= 2);
    let msg = test_mode(&["--time-offset-minus", "90"], &base_keys());
    assert!((msg.timestamp - (now - 90)).abs() <= 2);
}

#[test]
fn test_mode_with_spoof_user() {
    let msg = test_mode(&["--spoof-user", "alice"], &base_keys());
    assert_eq!(msg.username, "alice");
}

#[test]
fn source_ip_flag_requests_any_address() {
    let mut args: Vec<&str> = BASE
        .iter()
        .copied()
        .filter(|a| *a != "10.0.0.1" && *a != "--allow-ip")
        .collect();
    args.extend_from_slice(&["-s", "-T"]);
    let out = run_args(&args).unwrap().out;
    let msg = SpaMessage::decrypt(&SpaData::new(out.trim_end()), &base_keys()).unwrap();
    assert_eq!(msg.request.message_text(), "0.0.0.0,tcp/22");
}

#[test]
fn verbose_details() {
    let mut args = BASE.to_vec();
    args.extend_from_slice(&["-T", "-vv", "--spoof-user", "bob"]);
    let err = run_args(&args).unwrap().err;
    for want in [
        "SPA message details:",
        "  Username:     bob",
        "  Message type: Access",
        "  Access:       10.0.0.1,tcp/22",
        "  Digest:       SHA256",
        "  Encryption:   CBC",
        "  HMAC:         HMAC-SHA256",
        "SPA data length: ",
        "SPA data: ",
    ] {
        assert!(err.contains(want), "missing {want:?} in\n{err}");
    }
}

#[test]
fn missing_destination() {
    let args: Vec<&str> = BASE[2..].to_vec();
    let err = run_args(&args).unwrap_err().to_string();
    assert!(err.contains("destination"), "{err}");
}

#[test]
fn missing_access() {
    let args = [
        "--destination",
        "127.0.0.1",
        "--allow-ip",
        "10.0.0.1",
        "--key",
        "k",
        "--key-hmac",
        "h",
        "--no-rc-file",
    ];
    let err = run_args(&args).unwrap_err().to_string();
    assert!(err.contains("access"), "{err}");
}

#[test]
fn missing_key() {
    let args = &BASE[..6];
    let mut args = args.to_vec();
    args.push("--no-rc-file");
    let err = run_args(&args).unwrap_err().to_string();
    assert!(err.contains("key"), "{err}");
}

#[test]
fn missing_source_ip() {
    let args = [
        "--destination",
        "127.0.0.1",
        "--access",
        "tcp/22",
        "--key",
        "k",
        "--key-hmac",
        "h",
        "--no-rc-file",
    ];
    let err = run_args(&args).unwrap_err().to_string();
    assert!(err.contains("IP"), "{err}");
}

#[test]
fn bad_names_are_reported_like_go() {
    let cases = [
        (
            &["--digest-type", "sha999"][..],
            "unknown digest type: sha999",
        ),
        (
            &["--hmac-digest-type", "nope"][..],
            "unknown HMAC type: nope",
        ),
        (
            &["--encryption-mode", "ecb"][..],
            "unknown encryption mode: ecb (use cbc or legacy)",
        ),
    ];
    for (extra, want) in cases {
        let mut args = BASE.to_vec();
        args.extend_from_slice(extra);
        let err = run_args(&args).unwrap_err().to_string();
        assert_eq!(err, want);
    }
}

#[test]
fn multi_port_access_is_rejected() {
    let mut args = BASE.to_vec();
    args.extend_from_slice(&["-A", "tcp/22,tcp/443", "-T"]);
    let err = format!("{:#}", run_args(&args).unwrap_err());
    assert!(err.contains("invalid proto/port"), "{err}");
}

#[test]
fn repeated_flags_keep_the_last_value() {
    let mut args = BASE.to_vec();
    args.extend_from_slice(&["-A", "udp/53", "-T"]);
    let out = run_args(&args).unwrap().out;
    let msg = SpaMessage::decrypt(&SpaData::new(out.trim_end()), &base_keys()).unwrap();
    assert_eq!(msg.request.message_text(), "10.0.0.1,udp/53");
}

#[test]
fn sends_a_packet() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let port = server.local_addr().unwrap().port().to_string();
    let mut args = BASE.to_vec();
    args.extend_from_slice(&["-p", &port, "-v"]);
    let output = run_args(&args).unwrap();
    assert!(output.err.contains("SPA packet sent successfully."));

    let mut buf = [0u8; 1500];
    let n = server.recv(&mut buf).unwrap();
    let msg = SpaMessage::decrypt(&SpaData::from_bytes(&buf[..n]), &base_keys()).unwrap();
    assert_eq!(msg.request.message_text(), "10.0.0.1,tcp/22");
}

#[test]
fn stanza_list_prints_names_in_order() {
    let mut rc = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(
        &mut rc,
        b"zeta:\n  access: tcp/1\ndefault:\n  access: tcp/2\nalpha:\n",
    )
    .unwrap();
    let out = run_args(&["--stanza-list", "--rc-file", rc.path().to_str().unwrap()])
        .unwrap()
        .out;
    assert_eq!(out, "zeta\ndefault\nalpha\n");
}
