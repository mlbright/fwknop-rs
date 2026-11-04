//! Go ↔ Rust interoperability, run with `make interop`.
//!
//! The Makefile builds fwknop-go's binaries from `mlbright/main` and points
//! `FWKNOP_GO_BIN_DIR` at them. Without it these tests are skipped, so a
//! plain `cargo test` needs no Go toolchain.
//!
//! - Rust client → Go fwknopd, and Go client → Rust fwknopd, for every
//!   digest × HMAC × encryption mode, plus NAT, local NAT, client timeout,
//!   server command and replay.
//! - Both converters on the same legacy configs, compared after parsing.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HMACS: [&str; 7] = [
    "md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-512",
];
const DIGESTS: [&str; 7] = HMACS;
const MODES: [&str; 2] = ["cbc", "legacy"];

fn go_bin_dir() -> Option<PathBuf> {
    match std::env::var_os("FWKNOP_GO_BIN_DIR") {
        Some(dir) => Some(PathBuf::from(dir)),
        None => {
            eprintln!(
                "FWKNOP_GO_BIN_DIR is not set; skipping Go interop tests (run `make interop`)"
            );
            None
        }
    }
}

fn rust_bin(name: &str) -> PathBuf {
    let dir = std::env::var_os("FWKNOP_RS_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug"));
    let path = dir.join(name);
    assert!(
        path.exists(),
        "{} not built; run `make interop`",
        path.display()
    );
    path
}

/// A server running in the foreground in test mode, with its log captured.
struct Server {
    child: Child,
    log: Arc<Mutex<Vec<String>>>,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Server {
    fn start(bin: &Path) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let server_yaml = dir.path().join("server.yaml");
        std::fs::write(
            &server_yaml,
            format!(
                "udp_port: {port}\nbind_address: \"127.0.0.1\"\nlog_file: \"\"\nsyslog_identity: \"\"\nmax_spa_packet_age: 120\n"
            ),
        )
        .unwrap();
        let access_yaml = dir.path().join("access.yaml");
        std::fs::write(&access_yaml, access_stanzas()).unwrap();

        let mut child = Command::new(bin)
            .arg("-c")
            .arg(&server_yaml)
            .arg("-a")
            .arg(&access_yaml)
            .args(["-f", "-t", "-v"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&log);
        let pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                lines.lock().unwrap().push(line);
            }
        });
        let s = Server {
            child,
            log,
            port,
            _dir: dir,
        };
        s.wait_for(
            |l| l.iter().any(|x| x.contains("UDP server listening")),
            "startup",
        );
        s
    }

    fn count(&self, needle: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(needle))
            .count()
    }

    fn wait_for(&self, cond: impl Fn(&[String]) -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if cond(&self.log.lock().unwrap()) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}\n{}",
                self.log.lock().unwrap().join("\n")
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_count(&self, needle: &str, n: usize) {
        self.wait_for(
            |l| l.iter().filter(|x| x.contains(needle)).count() >= n,
            needle,
        );
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One access stanza per HMAC type × encryption mode, each with its own
/// keys, so every combination decrypts against exactly one of them.
fn access_stanzas() -> String {
    let mut out = String::new();
    for (hmac, mode) in combos() {
        let (key, hmac_key) = keys(hmac, mode);
        out.push_str(&format!(
            "- source: ANY\n  key: \"{key}\"\n  hmac_key: \"{hmac_key}\"\n  hmac_digest_type: {hmac}\n  encryption_mode: {mode}\n  enable_cmd_exec: true\n"
        ));
    }
    out
}

fn combos() -> Vec<(&'static str, &'static str)> {
    HMACS
        .iter()
        .flat_map(|h| MODES.iter().map(move |m| (*h, *m)))
        .collect()
}

fn keys(hmac: &str, mode: &str) -> (String, String) {
    (format!("enc-{hmac}-{mode}"), format!("hmac-{hmac}-{mode}"))
}

fn client(bin: &Path, port: u16, hmac: &str, mode: &str, extra: &[&str]) -> Command {
    let (key, hmac_key) = keys(hmac, mode);
    let mut c = Command::new(bin);
    c.args(["--no-rc-file", "-D", "127.0.0.1", "-p", &port.to_string()])
        .args(["--key", &key, "--key-hmac", &hmac_key])
        .args(["--hmac-digest-type", hmac, "--encryption-mode", mode])
        .args(extra);
    c
}

fn run_ok(mut c: Command) -> String {
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "{c:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Sends every combination and the message variants from `client_bin` to a
/// `server_bin` in test mode. `stanza_word` is how that server names access
/// stanzas in its log ("stanza" for Go, "access stanza" for Rust).
fn exercise(client_bin: &Path, server_bin: &Path, stanza_word: &str, check_digest_names: bool) {
    let server = Server::start(server_bin);
    let mut sent = 0;
    for (i, (hmac, mode)) in combos().into_iter().enumerate() {
        for digest in DIGESTS {
            run_ok(client(
                client_bin,
                server.port,
                hmac,
                mode,
                &["-A", "tcp/22", "-a", "127.0.0.1", "-m", digest],
            ));
            sent += 1;
            server.wait_count("decrypted successfully", sent);
            let n = i + 1;
            assert_eq!(
                server.count(&format!(
                    "({stanza_word} #{n}) SPA packet from 127.0.0.1 decrypted successfully"
                )),
                DIGESTS.iter().position(|d| *d == digest).unwrap() + 1,
                "{hmac}/{mode}/{digest} should decrypt against {stanza_word} #{n}"
            );
            if check_digest_names {
                let want = digest.to_uppercase();
                server.wait_count(&format!("  Digest Type:  {want}"), 1);
            }
        }
    }
    assert_eq!(server.count("No matching access stanza"), 0);
    assert_eq!(server.count("--test mode enabled, skipping action."), sent);

    let variants: [(&[&str], &str); 4] = [
        (
            &["-A", "tcp/22", "-a", "10.1.1.1", "-N", "192.168.1.5,22"],
            "  Message Type: NATAccess",
        ),
        (
            &[
                "-A",
                "udp/53",
                "-a",
                "10.1.1.2",
                "-N",
                "127.0.0.1,2222",
                "--nat-local",
                "-f",
                "45",
            ],
            "  Message Type: ClientTimeoutLocalNATAccess",
        ),
        (
            &["-A", "tcp/443", "-a", "10.1.1.3", "-f", "30"],
            "  Timeout:      30s",
        ),
        (
            &["-C", "uptime", "-a", "10.1.1.4"],
            "  Message Type: Command",
        ),
    ];
    for (args, want) in variants {
        run_ok(client(client_bin, server.port, "sha256", "cbc", args));
        server.wait_count(want, 1);
    }
    server.wait_count("  Access:       10.1.1.1,tcp/22", 1);
    server.wait_count("  NAT Access:   127.0.0.1,2222", 1);
    server.wait_count("  Access:       uptime", 1);

    // Replay: the same SPA data twice.
    let data = run_ok(client(
        client_bin,
        server.port,
        "sha512",
        "legacy",
        &["-A", "tcp/22", "-a", "127.0.0.1", "-T"],
    ));
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..2 {
        sock.send_to(data.trim_end().as_bytes(), ("127.0.0.1", server.port))
            .unwrap();
    }
    server.wait_count("Replay detected from 127.0.0.1", 1);
}

#[test]
fn rust_client_to_go_server() {
    let Some(go) = go_bin_dir() else { return };
    // Go's server labels SHA3 digests as SHA256/SHA512, so names are not
    // checked in this direction.
    exercise(&rust_bin("fwknop"), &go.join("fwknopd"), "stanza", false);
}

#[test]
fn go_client_to_rust_server() {
    let Some(go) = go_bin_dir() else { return };
    exercise(
        &go.join("fwknop"),
        &rust_bin("fwknopd"),
        "access stanza",
        true,
    );
}

#[test]
fn rust_and_go_test_mode_output_decrypts_both_ways() {
    let Some(go) = go_bin_dir() else { return };
    // Each client's -T output is accepted by the other implementation's
    // server (exercise() covers that over UDP); here just check both
    // clients agree on the plaintext shape by round-tripping through fkospa.
    for bin in [go.join("fwknop"), rust_bin("fwknop")] {
        let out = run_ok(client(
            &bin,
            62201,
            "sha256",
            "cbc",
            &["-A", "tcp/22", "-a", "127.0.0.1", "-T", "-U", "interop"],
        ));
        let keys = fkospa::KeySet::new(
            fkospa::EncryptionKey::new("enc-sha256-cbc"),
            fkospa::EncryptionMode::Cbc,
            Some(fkospa::HmacKey::new(
                "hmac-sha256-cbc",
                fkospa::HmacType::Sha256,
            )),
        );
        let msg =
            fkospa::SpaMessage::decrypt(&fkospa::SpaData::new(out.trim_end()), &keys).unwrap();
        assert_eq!(msg.username, "interop");
        assert_eq!(msg.request.message_text(), "127.0.0.1,tcp/22");
    }
}

// ---- converters ----

/// A parsed YAML value, for comparing the two converters' output.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(untagged)]
enum Yaml {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Yaml>),
    Map(BTreeMap<String, Yaml>),
    Null(()),
}

fn convert(bin: &Path, kind: &str, input: &str) -> Yaml {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(input);
    let out = Command::new(bin)
        .args(["--type", kind, "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    serde_saphyr::from_str(&text).unwrap_or_else(|e| panic!("{bin:?} {kind}: {e}\n{text}"))
}

/// Applies the documented differences to Go's output: values fwknop-go
/// wrote as strings that its own binaries could not load become typed, and
/// keys nothing reads (`run_dir`, `nat_port`) are dropped.
fn normalise_go(y: Yaml) -> Yaml {
    match y {
        Yaml::Map(m) => Yaml::Map(
            m.into_iter()
                .filter(|(k, _)| k != "run_dir" && k != "nat_port")
                .map(|(k, v)| {
                    let v = match (k.as_str(), v) {
                        ("use_hmac" | "nat_local" | "resolve_ip", Yaml::Str(s)) => Yaml::Bool(
                            matches!(s.to_uppercase().as_str(), "Y" | "YES" | "1" | "TRUE"),
                        ),
                        (
                            "udp_port" | "max_spa_packet_age" | "server_port" | "fw_timeout"
                            | "access_timeout" | "max_access_timeout",
                            Yaml::Str(s),
                        ) => s.parse().map(Yaml::Int).unwrap_or(Yaml::Str(s)),
                        ("verbose", Yaml::Str(s)) => match s.parse::<i64>() {
                            Ok(n) => Yaml::Bool(n != 0),
                            Err(_) => Yaml::Bool(matches!(
                                s.to_uppercase().as_str(),
                                "Y" | "YES" | "TRUE"
                            )),
                        },
                        (_, v) => normalise_go(v),
                    };
                    (k, v)
                })
                .collect(),
        ),
        Yaml::List(items) => Yaml::List(items.into_iter().map(normalise_go).collect()),
        other => other,
    }
}

/// fwknop-rs keeps a C client `VERBOSE Y` as a bool where the server's is
/// also a bool; compare the client's verbose the same way.
fn normalise_rust(y: Yaml) -> Yaml {
    match y {
        Yaml::Map(m) => Yaml::Map(
            m.into_iter()
                .map(|(k, v)| match (k.as_str(), v) {
                    ("verbose", Yaml::Int(n)) => (k, Yaml::Bool(n != 0)),
                    (_, v) => (k, normalise_rust(v)),
                })
                .collect(),
        ),
        Yaml::List(items) => Yaml::List(items.into_iter().map(normalise_rust).collect()),
        other => other,
    }
}

#[test]
fn converters_agree() {
    let Some(go) = go_bin_dir() else { return };
    let rust = rust_bin("fwknop-convert");
    for (kind, input) in [
        ("client", "fwknoprc"),
        ("server", "fwknopd.conf"),
        ("access", "access.conf"),
    ] {
        let from_go = normalise_go(convert(&go.join("fwknop-convert"), kind, input));
        let from_rust = normalise_rust(convert(&rust, kind, input));
        assert_eq!(from_rust, from_go, "{kind}");
    }
}
