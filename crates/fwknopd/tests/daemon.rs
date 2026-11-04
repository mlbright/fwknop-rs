//! End-to-end tests that run the fwknopd binary.

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage};

const BIN: &str = env!("CARGO_BIN_EXE_fwknopd");

struct Daemon {
    child: Child,
    stderr: Arc<Mutex<Vec<String>>>,
}

impl Daemon {
    fn start(args: &[&str]) -> Daemon {
        let mut child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&stderr);
        let pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                lines.lock().unwrap().push(line);
            }
        });
        let d = Daemon { child, stderr };
        d.wait_for_log("UDP server listening");
        d
    }

    fn log_contains(&self, needle: &str) -> bool {
        self.stderr
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains(needle))
    }

    fn count(&self, needle: &str) -> usize {
        self.stderr
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(needle))
            .count()
    }

    fn wait_for_log(&self, needle: &str) {
        wait_until(
            || self.log_contains(needle),
            || self.stderr.lock().unwrap().join("\n"),
            needle,
        );
    }

    fn signal(&self, sig: nix::sys::signal::Signal) {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(self.child.id() as i32), sig).unwrap();
    }

    fn wait_exit(mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "fwknopd did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_until(mut cond: impl FnMut() -> bool, context: impl Fn() -> String, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what:?}\n{}",
            context()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Setup {
    dir: tempfile::TempDir,
    port: u16,
}

impl Setup {
    fn new() -> Setup {
        Setup {
            dir: tempfile::tempdir().unwrap(),
            port: free_port(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn p(&self, name: &str) -> String {
        self.path(name).to_str().unwrap().to_string()
    }

    fn write_server(&self, bind: &str, log_file: &str) {
        let actions = self.p("actions.log");
        let text = format!(
            "udp_port: {port}\nbind_address: \"{bind}\"\nlog_file: \"{log_file}\"\nsyslog_identity: \"\"\n\
             pid_file: {pid}\nmax_spa_packet_age: 120\nactions:\n\
             \x20 init: \"echo init >> {actions}\"\n\
             \x20 open: \"echo open {{{{.SourceIP}}}} {{{{.Port}}}} >> {actions}\"\n\
             \x20 close: \"echo close {{{{.SourceIP}}}} {{{{.Port}}}} >> {actions}\"\n\
             \x20 shutdown: \"echo shutdown >> {actions}\"\n",
            port = self.port,
            pid = self.p("fwknopd.pid"),
        );
        std::fs::write(self.path("server.yaml"), text).unwrap();
    }

    fn write_access(&self, key: &str, timeout: u32) {
        std::fs::write(
            self.path("access.yaml"),
            format!("- source: ANY\n  key: {key}\n  hmac_key: hmac\n  access_timeout: {timeout}\n"),
        )
        .unwrap();
    }

    fn args(&self) -> Vec<String> {
        vec![
            "-c".into(),
            self.p("server.yaml"),
            "-a".into(),
            self.p("access.yaml"),
        ]
    }

    fn actions_log(&self) -> String {
        std::fs::read_to_string(self.path("actions.log")).unwrap_or_default()
    }

    fn wait_for_action(&self, needle: &str) {
        wait_until(
            || self.actions_log().contains(needle),
            || self.actions_log(),
            needle,
        );
    }

    fn knock(&self, to: &str, key: &str, access: &str) {
        let keys = KeySet::new(
            EncryptionKey::new(key),
            EncryptionMode::Cbc,
            Some(HmacKey::new("hmac", HmacType::Sha256)),
        );
        let msg = SpaMessage::new(Request::access(access.parse().unwrap())).unwrap();
        let data = msg.encrypt(&keys).unwrap();
        let local = if to.contains(':') {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let sock = UdpSocket::bind(local).unwrap();
        sock.send_to(
            data.as_str().as_bytes(),
            format!("{}:{}", bracket(to), self.port),
        )
        .unwrap();
    }
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn args_ref(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[test]
fn opens_closes_and_shuts_down() {
    let s = Setup::new();
    s.write_server("127.0.0.1", "");
    s.write_access("key1", 1);
    let mut args = s.args();
    args.push("-f".into());
    let d = Daemon::start(&args_ref(&args));
    s.wait_for_action("init");

    s.knock("127.0.0.1", "key1", "127.0.0.1,tcp/22");
    s.wait_for_action("open 127.0.0.1 22");
    // access_timeout is 1 second.
    s.wait_for_action("close 127.0.0.1 22");

    s.knock("127.0.0.1", "key1", "127.0.0.1,tcp/443");
    s.wait_for_action("open 127.0.0.1 443");
    d.signal(nix::sys::signal::Signal::SIGTERM);
    d.wait_for_log("Received signal terminated, shutting down...");
    let status = d.wait_exit();
    assert!(status.success(), "{status}");
    let log = s.actions_log();
    assert!(log.contains("close 127.0.0.1 443"), "{log}");
    assert!(log.trim_end().ends_with("shutdown"), "{log}");
}

#[test]
fn sighup_restarts_with_new_config_or_keeps_the_old_one() {
    let s = Setup::new();
    s.write_server("127.0.0.1", "");
    s.write_access("key1", 60);
    let mut args = s.args();
    args.push("-f".into());
    let d = Daemon::start(&args_ref(&args));

    s.knock("127.0.0.1", "key1", "127.0.0.1,tcp/22");
    s.wait_for_action("open 127.0.0.1 22");

    // A valid new configuration: open rules are closed, shutdown and init
    // run, and the new key is used.
    s.write_access("key2", 60);
    d.signal(nix::sys::signal::Signal::SIGHUP);
    d.wait_for_log("Restarted: loaded 1 access stanza(s)");
    let log = s.actions_log();
    assert!(
        log.contains("close 127.0.0.1 22\nshutdown\ninit\n"),
        "{log}"
    );

    s.knock("127.0.0.1", "key1", "127.0.0.1,tcp/80");
    d.wait_for_log("No matching access stanza for SPA packet from 127.0.0.1");
    s.knock("127.0.0.1", "key2", "127.0.0.1,tcp/80");
    s.wait_for_action("open 127.0.0.1 80");

    // An invalid new configuration: nothing changes.
    std::fs::write(s.path("access.yaml"), "- source: [broken\n").unwrap();
    d.signal(nix::sys::signal::Signal::SIGHUP);
    d.wait_for_log("Restart failed, keeping the current configuration");
    assert_eq!(s.actions_log().matches("shutdown").count(), 1);
    s.knock("127.0.0.1", "key2", "127.0.0.1,tcp/8080");
    s.wait_for_action("open 127.0.0.1 8080");

    d.signal(nix::sys::signal::Signal::SIGINT);
    d.wait_for_log("Received signal interrupt, shutting down...");
    assert!(d.wait_exit().success());
}

#[test]
fn wildcard_bind_listens_on_ipv4_and_ipv6() {
    if UdpSocket::bind("[::1]:0").is_err() {
        return; // no IPv6 loopback
    }
    let s = Setup::new();
    s.write_server("0.0.0.0", "");
    s.write_access("key1", 60);
    let mut args = s.args();
    args.extend(["-f".into(), "-t".into()]);
    let d = Daemon::start(&args_ref(&args));
    s.knock("127.0.0.1", "key1", "127.0.0.1,tcp/22");
    s.knock("::1", "key1", "::1,tcp/22");
    d.wait_for_log("SPA packet from 127.0.0.1 decrypted successfully");
    d.wait_for_log("SPA packet from ::1 decrypted successfully");
    assert_eq!(d.count("--test mode enabled, skipping action."), 2);
}

#[test]
fn background_mode_uses_the_pid_file() {
    let s = Setup::new();
    s.write_server("127.0.0.1", &s.p("fwknopd.log"));
    s.write_access("key1", 60);
    let pid_file = s.p("fwknopd.pid");

    let status = Command::new(BIN).args(s.args()).status().unwrap();
    assert!(
        status.success(),
        "the starting process exits once the server detaches"
    );
    wait_until(|| Path::new(&pid_file).exists(), String::new, "PID file");
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let out = Command::new(BIN)
        .args(["-S", "-p", &pid_file])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("fwknopd is running (PID {pid}).\n")
    );

    let second = Command::new(BIN).args(s.args()).output().unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already running"));

    s.knock("127.0.0.1", "key1", "127.0.0.1,tcp/22");
    s.wait_for_action("open 127.0.0.1 22");

    let out = Command::new(BIN)
        .args(["-K", "-p", &pid_file])
        .output()
        .unwrap();
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("Sent signal terminated to fwknopd")
    );
    wait_until(
        || !Path::new(&pid_file).exists(),
        String::new,
        "PID file removal",
    );
    s.wait_for_action("shutdown");
    let log = std::fs::read_to_string(s.path("fwknopd.log")).unwrap();
    assert!(log.contains("[INFO] PID file written"), "{log}");
    assert!(
        log.contains("[INFO] Opened action rule for 127.0.0.1/tcp/22"),
        "{log}"
    );
}

#[test]
fn startup_errors_reach_the_terminal() {
    let s = Setup::new();
    s.write_server("127.0.0.1", "");
    std::fs::write(
        s.path("server.yaml"),
        std::fs::read_to_string(s.path("server.yaml"))
            .unwrap()
            .replace(
                "actions:\n",
                "actions:\n  validate: \"echo no firewall >&2; false\"\n",
            ),
    )
    .unwrap();
    s.write_access("key1", 60);
    // Without -f: the error must come out before the server detaches.
    let out = Command::new(BIN).args(s.args()).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        "fwknopd: action validate failed: exit status 1: no firewall"
    );
    assert!(!s.path("fwknopd.pid").exists());
}

#[test]
fn version_and_dump_config() {
    let out = Command::new(BIN).arg("-V").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("fwknopd (Rust) version 0.1.0"), "{text}");
    assert!(text.trim_end().ends_with("(SPA protocol 3.0.0)"));

    let s = Setup::new();
    s.write_server("127.0.0.1", "");
    s.write_access("key1", 45);
    let mut args = s.args();
    args.push("-D".into());
    let out = Command::new(BIN).args(&args).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for want in [
        "fwknopd configuration:",
        &format!("  UDP port:       {}", s.port),
        "  Bind address:   127.0.0.1",
        "Access stanzas (1):",
        "  Access stanza #1:",
        "    Source:           ANY",
        "    Open ports:       []",
        "    Access timeout:   45s",
        "    Enc key length:   4 bytes",
        "    HMAC key length:  4 bytes",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}
