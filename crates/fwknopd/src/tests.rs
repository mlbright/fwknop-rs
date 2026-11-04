//! Packet-processing tests ported from fwknop-go's cmd/fwknopd/server_test.go
//! and the template-context tests from actions_test.go.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Instant;

use fkospa::{
    DigestType, EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage,
};

use crate::access::{AccessStanza, RawStanza};
use crate::actions::{Actions, ActionsConfig};
use crate::config::ServerConfig;
use crate::log::Logger;
use crate::server::{
    Loaded, Server, contains_ip, effective_timeout, template_context, wall_clock_ns,
};

const ENC: &str = "test_enc_key_123";
const HMAC: &str = "test_hmac_key_456";

fn raw(source: &str) -> RawStanza {
    RawStanza {
        source: source.into(),
        key: ENC.into(),
        hmac_key: HMAC.into(),
        ..RawStanza::default()
    }
}

fn stanza(raw: RawStanza) -> AccessStanza {
    AccessStanza::resolve(raw).unwrap()
}

fn server(stanzas: Vec<AccessStanza>, test_mode: bool, actions: ActionsConfig) -> Server {
    let cfg = ServerConfig {
        max_spa_packet_age: 120,
        test: test_mode,
        ..ServerConfig::default()
    };
    Server::new(
        Loaded {
            cfg,
            stanzas,
            actions: Actions::new(actions).unwrap(),
        },
        Logger::capture(),
    )
}

fn test_server(stanzas: Vec<AccessStanza>) -> Server {
    server(stanzas, true, ActionsConfig::default())
}

fn keys(enc: &str, hmac: Option<(&str, HmacType)>, mode: EncryptionMode) -> KeySet {
    KeySet::new(
        EncryptionKey::new(enc),
        mode,
        hmac.map(|(k, t)| HmacKey::new(k, t)),
    )
}

fn default_keys() -> KeySet {
    keys(ENC, Some((HMAC, HmacType::Sha256)), EncryptionMode::Cbc)
}

fn message(access: &str) -> SpaMessage {
    SpaMessage::new(Request::access(access.parse().unwrap())).unwrap()
}

fn packet(msg: &SpaMessage, keys: &KeySet) -> Vec<u8> {
    msg.encrypt(keys).unwrap().into_string().into_bytes()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn process(s: &mut Server, data: &[u8], src: &str) {
    s.process_packet(data, ip(src), Instant::now(), wall_clock_ns());
}

#[test]
fn success() {
    let mut s = test_server(vec![stanza(raw("ANY"))]);
    process(
        &mut s,
        &packet(&message("127.0.0.1,tcp/22"), &default_keys()),
        "127.0.0.1",
    );
    assert!(
        s.log
            .contains("(access stanza #1) SPA packet from 127.0.0.1 decrypted successfully")
    );
    assert!(s.log.contains("  Access:       127.0.0.1,tcp/22"));
    assert!(
        s.log
            .contains("(access stanza #1) --test mode enabled, skipping action.")
    );
}

#[test]
fn no_matching_stanza() {
    let mut s = test_server(vec![stanza(raw("192.168.1.0/24"))]);
    process(
        &mut s,
        &packet(&message("10.0.0.1,tcp/22"), &default_keys()),
        "10.0.0.1",
    );
    assert!(
        s.log
            .contains("No matching access stanza for SPA packet from 10.0.0.1")
    );
    assert!(!s.log.contains("decrypted successfully"));
}

#[test]
fn wrong_key() {
    let mut s = test_server(vec![stanza(RawStanza {
        key: "wrong_key_000000".into(),
        ..raw("ANY")
    })]);
    let k = keys(
        "correct_key_1234",
        Some((HMAC, HmacType::Sha256)),
        EncryptionMode::Cbc,
    );
    process(&mut s, &packet(&message("10.0.0.1,tcp/22"), &k), "10.0.0.1");
    assert!(s.log.contains("No matching access stanza"));
    assert!(s.log.contains("Access stanza #1 decrypt failed"));
}

#[test]
fn replay_rejected() {
    let mut s = test_server(vec![stanza(raw("ANY"))]);
    let data = packet(&message("10.0.0.1,tcp/22"), &default_keys());
    process(&mut s, &data, "10.0.0.1");
    process(&mut s, &data, "10.0.0.1");
    assert!(s.log.contains("Replay detected from 10.0.0.1"));
    assert_eq!(
        s.log
            .lines()
            .iter()
            .filter(|l| l.contains("--test mode enabled"))
            .count(),
        1
    );
}

#[test]
fn replay_rejected_when_max_age_is_zero() {
    let mut s = test_server(vec![stanza(raw("ANY"))]);
    s.cfg.max_spa_packet_age = 0;
    s.replay = crate::replay::ReplayCache::new(crate::replay::ReplayCache::ttl_for_max_age(0));
    let data = packet(&message("10.0.0.1,tcp/22"), &default_keys());
    process(&mut s, &data, "10.0.0.1");
    process(&mut s, &data, "10.0.0.1");
    assert!(s.log.contains("Replay detected"));
}

#[test]
fn tries_multiple_stanzas() {
    let first = stanza(RawStanza {
        key: "other_key".into(),
        ..raw("ANY")
    });
    let mut s = test_server(vec![first, stanza(raw("ANY"))]);
    process(
        &mut s,
        &packet(&message("10.0.0.1,tcp/22"), &default_keys()),
        "10.0.0.1",
    );
    assert!(s.log.contains("Access stanza #1 decrypt failed"));
    assert!(
        s.log
            .contains("(access stanza #2) SPA packet from 10.0.0.1 decrypted successfully")
    );
}

#[test]
fn old_and_future_packets_rejected() {
    let mut s = test_server(vec![stanza(raw("ANY"))]);
    let mut old = message("10.0.0.1,tcp/22");
    old.timestamp -= 300;
    process(&mut s, &packet(&old, &default_keys()), "10.0.0.1");
    // The age is rounded to the second, so it reads 5m0s or 5m1s.
    assert!(s.log.lines().iter().any(|l| {
        (l.contains("is too old (age: 5m0s,") || l.contains("is too old (age: 5m1s,"))
            && l.contains("SPA packet from 10.0.0.1")
            && l.ends_with("max: 120s)")
    }));

    let mut future = message("10.0.0.1,tcp/22");
    future.timestamp += 300;
    process(&mut s, &packet(&future, &default_keys()), "10.0.0.1");
    assert!(s.log.lines().iter().any(|l| {
        l.contains("SPA packet from 10.0.0.1 is timestamped in the future (by ")
            && (l.contains("by 5m0s,") || l.contains("by 4m59s,"))
            && l.ends_with("max: 120s)")
    }));
    assert!(!s.log.contains("--test mode enabled"));

    let mut recent = message("10.0.0.1,tcp/22");
    recent.timestamp -= 100;
    process(&mut s, &packet(&recent, &default_keys()), "10.0.0.1");
    assert!(s.log.contains("--test mode enabled"));
}

#[test]
fn require_username() {
    let required = || {
        stanza(RawStanza {
            require_username: "alice".into(),
            ..raw("ANY")
        })
    };
    let mut s = test_server(vec![required()]);
    let mut m = message("10.0.0.1,tcp/22");
    m.username = "alice".into();
    process(&mut s, &packet(&m, &default_keys()), "10.0.0.1");
    assert!(s.log.contains("--test mode enabled"));

    let mut s = test_server(vec![required()]);
    m.username = "mallory".into();
    process(&mut s, &packet(&m, &default_keys()), "10.0.0.1");
    assert!(
        s.log
            .contains(r#"Username mismatch: got "mallory", required "alice""#)
    );
    assert!(!s.log.contains("--test mode enabled"));
}

#[test]
fn require_source_address() {
    let required = || {
        stanza(RawStanza {
            require_source_address: true,
            ..raw("ANY")
        })
    };
    let mut s = test_server(vec![required()]);
    process(
        &mut s,
        &packet(&message("10.0.0.1,tcp/22"), &default_keys()),
        "10.0.0.1",
    );
    assert!(s.log.contains("--test mode enabled"));

    let mut s = test_server(vec![required()]);
    process(
        &mut s,
        &packet(&message("10.0.0.1,tcp/22"), &default_keys()),
        "10.0.0.99",
    );
    assert!(s.log.contains(
        r#"Source address mismatch: SPA from 10.0.0.99 but access msg is "10.0.0.1,tcp/22""#
    ));

    // 0.0.0.0 never equals a packet source.
    let mut s = test_server(vec![required()]);
    process(
        &mut s,
        &packet(&message("0.0.0.0,tcp/22"), &default_keys()),
        "10.0.0.1",
    );
    assert!(s.log.contains("Source address mismatch"));
}

#[test]
fn every_digest_and_hmac_combination() {
    for hmac in HmacType::ALL {
        for mode in [EncryptionMode::Cbc, EncryptionMode::CbcLegacyIv] {
            let mode_name = if mode == EncryptionMode::Cbc {
                "cbc"
            } else {
                "legacy"
            };
            let hmac_name = hmac.to_string().trim_start_matches("HMAC-").to_lowercase();
            let st = stanza(RawStanza {
                hmac_digest_type: hmac_name,
                encryption_mode: mode_name.into(),
                ..raw("ANY")
            });
            let mut s = test_server(vec![st]);
            for digest in DigestType::ALL {
                let mut m = message("10.0.0.1,tcp/22");
                m.digest_type = digest;
                process(
                    &mut s,
                    &packet(&m, &keys(ENC, Some((HMAC, hmac)), mode)),
                    "10.0.0.1",
                );
                assert!(
                    s.log.contains(&format!("  Digest Type:  {digest}")),
                    "{digest} / {hmac} / {mode}"
                );
            }
            assert_eq!(
                s.log
                    .lines()
                    .iter()
                    .filter(|l| l.contains("decrypted successfully"))
                    .count(),
                7,
                "{hmac} / {mode}"
            );
        }
    }
}

#[test]
fn stanza_without_hmac_key_accepts_unauthenticated_packets() {
    let mut s = test_server(vec![stanza(RawStanza {
        hmac_key: String::new(),
        ..raw("ANY")
    })]);
    let k = keys(ENC, None, EncryptionMode::Cbc);
    process(&mut s, &packet(&message("10.0.0.1,tcp/22"), &k), "10.0.0.1");
    assert!(s.log.contains("decrypted successfully"));
}

#[test]
fn nat_access_and_client_timeout_are_logged() {
    let mut s = test_server(vec![stanza(raw("ANY"))]);
    let m = SpaMessage::new(Request::NatAccess {
        access: "10.0.0.1,tcp/22".parse().unwrap(),
        nat_access: "192.168.1.100,22".into(),
        client_timeout: NonZeroU32::new(45),
    })
    .unwrap();
    process(&mut s, &packet(&m, &default_keys()), "10.0.0.1");
    assert!(s.log.contains("  Message Type: ClientTimeoutNATAccess"));
    assert!(s.log.contains("  NAT Access:   192.168.1.100,22"));
    assert!(s.log.contains("  Timeout:      45s"));
}

#[test]
fn ipv6_and_ipv4_mapped_sources() {
    let mut s = test_server(vec![stanza(raw("2001:db8::/32"))]);
    process(
        &mut s,
        &packet(&message("2001:db8::1,tcp/22"), &default_keys()),
        "2001:db8::1",
    );
    assert!(
        s.log
            .contains("SPA packet from 2001:db8::1 decrypted successfully")
    );

    // A dual-stack socket reports IPv4 senders as ::ffff:a.b.c.d.
    let mut s = test_server(vec![stanza(raw("127.0.0.0/8"))]);
    process(
        &mut s,
        &packet(&message("127.0.0.1,tcp/22"), &default_keys()),
        "::ffff:127.0.0.1",
    );
    assert!(
        s.log
            .contains("SPA packet from 127.0.0.1 decrypted successfully")
    );
}

#[test]
fn contains_ip_normalises() {
    assert!(contains_ip("2001:db8::1,tcp/22", ip("2001:0db8:0000::1")));
    assert!(contains_ip("::ffff:10.0.0.1,tcp/22", ip("10.0.0.1")));
    assert!(contains_ip("10.0.0.1,tcp/22", ip("10.0.0.1")));
    assert!(!contains_ip("10.0.0.2,tcp/22", ip("10.0.0.1")));
    assert!(!contains_ip("uptime", ip("10.0.0.1")));
}

// ---- dispatching actions ----

fn recording_actions(dir: &tempfile::TempDir) -> (ActionsConfig, std::path::PathBuf) {
    let log = dir.path().join("actions.log");
    let cfg = ActionsConfig {
        open: format!(
            "echo open {{{{.SourceIP}}}} {{{{.Proto}}}} {{{{.Port}}}} {{{{.Timeout}}}} {{{{.Username}}}} >> {}",
            log.display()
        ),
        close: format!("echo close {{{{.SourceIP}}}} >> {}", log.display()),
        ..ActionsConfig::default()
    };
    (cfg, log)
}

#[test]
fn access_request_opens_a_rule() {
    let dir = tempfile::tempdir().unwrap();
    let (actions, log_path) = recording_actions(&dir);
    let mut s = server(vec![stanza(raw("ANY"))], false, actions);
    let mut m = message("10.0.0.1,tcp/22");
    m.username = "alice".into();
    process(&mut s, &packet(&m, &default_keys()), "10.0.0.1");
    assert_eq!(
        std::fs::read_to_string(&log_path).unwrap(),
        "open 10.0.0.1 tcp 22 30 alice\n"
    );
    assert_eq!(s.actions.active_rule_count(), 1);
}

#[test]
fn any_address_request_opens_for_the_packet_source() {
    let dir = tempfile::tempdir().unwrap();
    let (actions, log_path) = recording_actions(&dir);
    let mut s = server(vec![stanza(raw("ANY"))], false, actions);
    process(
        &mut s,
        &packet(&message("0.0.0.0,tcp/22"), &default_keys()),
        "172.16.0.50",
    );
    let text = std::fs::read_to_string(&log_path).unwrap();
    assert!(text.starts_with("open 172.16.0.50 tcp 22"), "{text}");
}

#[test]
fn port_not_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let (actions, log_path) = recording_actions(&dir);
    let st = stanza(RawStanza {
        open_ports: vec!["tcp/22".into()],
        ..raw("ANY")
    });
    let mut s = server(vec![st], false, actions);
    process(
        &mut s,
        &packet(&message("10.0.0.1,tcp/443"), &default_keys()),
        "10.0.0.1",
    );
    assert!(
        s.log
            .contains("(access stanza #1) Port tcp/443 not allowed by open_ports")
    );
    assert!(!log_path.exists());
}

#[test]
fn server_command_runs_only_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let cmd = format!("touch {}", marker.display());
    let command_packet = || {
        let m = SpaMessage::new(Request::Command(cmd.clone())).unwrap();
        packet(&m, &default_keys())
    };

    let mut s = server(vec![stanza(raw("ANY"))], false, ActionsConfig::default());
    process(&mut s, &command_packet(), "10.0.0.1");
    assert!(
        s.log
            .contains("CommandMsg from 10.0.0.1 but enable_cmd_exec is false")
    );
    assert!(!marker.exists());

    let enabled = stanza(RawStanza {
        enable_cmd_exec: true,
        ..raw("ANY")
    });
    let mut s = server(vec![enabled], false, ActionsConfig::default());
    process(&mut s, &command_packet(), "10.0.0.1");
    assert!(
        s.log
            .contains("(access stanza #1) Executing command from 10.0.0.1")
    );
    assert!(marker.exists());
}

#[test]
fn failed_open_is_logged() {
    let actions = ActionsConfig {
        open: "exit 4".into(),
        ..ActionsConfig::default()
    };
    let mut s = server(vec![stanza(raw("ANY"))], false, actions);
    process(
        &mut s,
        &packet(&message("10.0.0.1,tcp/22"), &default_keys()),
        "10.0.0.1",
    );
    assert!(s.log.contains(
        "(access stanza #1) Failed to open access rule: open command failed for 10.0.0.1/tcp/22: exit status 4"
    ));
    assert_eq!(s.actions.active_rule_count(), 0);
}

// ---- template context (actions_test.go) ----

#[test]
fn template_context_fields() {
    let st = stanza(raw("ANY"));
    let m = SpaMessage {
        username: "alice".into(),
        request: Request::NatAccess {
            access: "10.0.0.1,tcp/22".parse().unwrap(),
            nat_access: "192.168.1.100,22".into(),
            client_timeout: NonZeroU32::new(60),
        },
        ..message("10.0.0.1,tcp/22")
    };
    let ctx = template_context(&m, ip("10.0.0.99"), &st).unwrap();
    assert_eq!(ctx.source_ip, "10.0.0.1");
    assert_eq!(ctx.proto, "tcp");
    assert_eq!(ctx.port, "22");
    assert_eq!(ctx.username, "alice");
    assert_eq!(ctx.timeout, 60);
    assert_eq!(ctx.nat_access, "192.168.1.100,22");
    assert_eq!(ctx.access_msg, "10.0.0.1,tcp/22");
}

#[test]
fn template_context_any_address_fallbacks() {
    let st = stanza(raw("ANY"));
    for (allow, src, want) in [
        ("0.0.0.0", "172.16.0.50", "172.16.0.50"),
        ("::", "2001:db8::1", "2001:db8::1"),
        ("0:0:0:0:0:0:0:0", "2001:db8::1", "2001:db8::1"),
        ("::ffff:0.0.0.0", "10.1.1.1", "10.1.1.1"),
        ("192.168.1.100", "10.0.0.1", "192.168.1.100"),
    ] {
        let ctx = template_context(&message(&format!("{allow},tcp/22")), ip(src), &st).unwrap();
        assert_eq!(ctx.source_ip, want, "{allow}");
    }
    let cmd = SpaMessage::new(Request::Command("uptime".into())).unwrap();
    assert!(template_context(&cmd, ip("10.0.0.1"), &st).is_none());
}

#[test]
fn effective_timeouts() {
    let st = stanza(RawStanza {
        access_timeout: 30,
        max_access_timeout: 300,
        ..raw("ANY")
    });
    let with = |t: u32| SpaMessage {
        request: Request::Access {
            access: "10.0.0.1,tcp/22".parse().unwrap(),
            client_timeout: NonZeroU32::new(t),
        },
        ..message("10.0.0.1,tcp/22")
    };
    assert_eq!(effective_timeout(&with(0), &st), 30);
    assert_eq!(effective_timeout(&with(60), &st), 60);
    assert_eq!(effective_timeout(&with(300), &st), 300);
    assert_eq!(effective_timeout(&with(600), &st), 300);
}

#[test]
fn go_duration_strings() {
    use crate::server::go_duration;
    assert_eq!(go_duration(0), "0s");
    assert_eq!(go_duration(45), "45s");
    assert_eq!(go_duration(240), "4m0s");
    assert_eq!(go_duration(3605), "1h0m5s");
    assert_eq!(go_duration(-299), "-4m59s");
}
