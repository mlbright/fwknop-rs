//! Actions and the rules they open.
//!
//! The server owns one [`Actions`]: the six actions (validate, init, check,
//! open, close, shutdown) and the table of rules it has opened, each with
//! the time it expires. Everything runs on the server's single event loop,
//! one command at a time, so rules cannot race with each other.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use serde::Deserialize;

use crate::log::Logger;
use crate::template::{Template, TemplateContext};

/// How long a server command may run.
const SERVER_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// The shell command for each lifecycle step. All optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ActionsConfig {
    pub validate: String,
    pub init: String,
    pub check: String,
    pub open: String,
    pub close: String,
    pub shutdown: String,
}

impl ActionsConfig {
    /// `override_`'s non-empty actions replace `self`'s.
    pub fn merged_with(&self, override_: &ActionsConfig) -> ActionsConfig {
        let pick = |base: &String, over: &String| {
            if over.is_empty() {
                base.clone()
            } else {
                over.clone()
            }
        };
        ActionsConfig {
            validate: pick(&self.validate, &override_.validate),
            init: pick(&self.init, &override_.init),
            check: pick(&self.check, &override_.check),
            open: pick(&self.open, &override_.open),
            close: pick(&self.close, &override_.close),
            shutdown: pick(&self.shutdown, &override_.shutdown),
        }
    }
}

/// Reads an action template. A bare file name is looked up in
/// `action_dir`.
pub fn load_action_template(template: &str, action_dir: &str) -> Result<ActionsConfig> {
    if template.is_empty() {
        return Ok(ActionsConfig::default());
    }
    let path = if Path::new(template).file_name().and_then(|n| n.to_str()) == Some(template) {
        Path::new(action_dir).join(template)
    } else {
        Path::new(template).to_path_buf()
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow!("reading action template {}: {e}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(ActionsConfig::default());
    }
    serde_saphyr::from_str::<ActionsConfig>(&text)
        .map_err(|e| anyhow!("parsing action template {}: {e}", path.display()))
}

/// A rule the server opened and will close.
#[derive(Debug, Clone)]
struct Rule {
    ctx: TemplateContext,
    expires: Instant,
}

/// The actions, with check/open/close parsed, and the open rules.
#[derive(Debug)]
pub struct Actions {
    cfg: ActionsConfig,
    check: Option<Template>,
    open: Option<Template>,
    close: Option<Template>,
    rules: HashMap<String, Rule>,
}

fn parse_optional(name: &str, text: &str) -> Result<Option<Template>> {
    if text.is_empty() {
        return Ok(None);
    }
    Template::parse(text)
        .map(Some)
        .map_err(|e| anyhow!("parsing {name} template: {e}"))
}

impl Actions {
    pub fn new(cfg: ActionsConfig) -> Result<Actions> {
        Ok(Actions {
            check: parse_optional("check", &cfg.check)?,
            open: parse_optional("open", &cfg.open)?,
            close: parse_optional("close", &cfg.close)?,
            cfg,
            rules: HashMap::new(),
        })
    }

    /// Runs the validate action; failure means the server must not start.
    pub fn validate(&self, log: &Logger) -> Result<()> {
        if self.cfg.validate.is_empty() {
            return Ok(());
        }
        log.info("Running action validate command...");
        run_shell(&self.cfg.validate, None)
            .map(|_| ())
            .map_err(|e| anyhow!("action validate failed: {e}"))
    }

    /// Runs the init action; failure means the server must not start.
    pub fn init(&self, log: &Logger) -> Result<()> {
        if self.cfg.init.is_empty() {
            return Ok(());
        }
        log.info("Running action init command...");
        run_shell(&self.cfg.init, None)
            .map(|_| ())
            .map_err(|e| anyhow!("action init failed: {e}"))
    }

    /// Opens a rule for `ctx`, or extends it if one is already open.
    ///
    /// A rule this server already tracks just gets a new expiry. Otherwise
    /// the check action decides: exit 0 means the rule already exists, and
    /// the server takes it over; anything else runs the open action.
    pub fn open_rule(&mut self, ctx: TemplateContext, now: Instant, log: &Logger) -> Result<()> {
        let key = rule_key(&ctx);
        if self.rules.contains_key(&key) {
            log.info(format!("Rule already open for {key}, refreshing timeout"));
            self.track(key, ctx, now);
            return Ok(());
        }

        if let Some(check) = &self.check
            && run_shell(&check.render(&ctx), None).is_ok()
        {
            log.info(format!("Rule already exists for {key}, refreshing timeout"));
            self.track(key, ctx, now);
            return Ok(());
        }

        if let Some(open) = &self.open {
            run_shell(&open.render(&ctx), None)
                .map_err(|e| anyhow!("open command failed for {key}: {e}"))?;
            log.info(format!(
                "Opened action rule for {key} (timeout: {}s)",
                ctx.timeout
            ));
        }
        self.track(key, ctx, now);
        Ok(())
    }

    fn track(&mut self, key: String, ctx: TemplateContext, now: Instant) {
        let timeout = Duration::from_secs(u64::try_from(ctx.timeout).unwrap_or(0));
        self.rules.insert(
            key,
            Rule {
                ctx,
                expires: now + timeout,
            },
        );
    }

    /// When the next rule expires.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.rules.values().map(|r| r.expires).min()
    }

    /// Closes every rule that has expired by `now`.
    pub fn close_expired(&mut self, now: Instant, log: &Logger) {
        let mut expired: Vec<(String, Rule)> = Vec::new();
        self.rules.retain(|key, rule| {
            if rule.expires <= now {
                expired.push((key.clone(), rule.clone()));
                false
            } else {
                true
            }
        });
        expired.sort_by_key(|(_, r)| r.expires);
        for (key, rule) in expired {
            self.run_close(&key, &rule.ctx, "", log);
        }
    }

    fn run_close(&self, key: &str, ctx: &TemplateContext, why: &str, log: &Logger) {
        let Some(close) = &self.close else {
            return;
        };
        match run_shell(&close.render(ctx), None) {
            Ok(_) => log.info(format!("Closed action rule for {key}{why}")),
            Err(e) => log.error(format!(
                "Close command failed for {key}{}: {e}",
                during(why)
            )),
        }
    }

    /// Closes every open rule, then runs the shutdown action.
    pub fn shutdown(&mut self, log: &Logger) {
        let mut rules: Vec<(String, Rule)> = self.rules.drain().collect();
        rules.sort_by_key(|(_, r)| r.expires);
        for (key, rule) in &rules {
            self.run_close(key, &rule.ctx, " (shutdown)", log);
        }
        if !self.cfg.shutdown.is_empty() {
            log.info("Running action shutdown command...");
            if let Err(e) = run_shell(&self.cfg.shutdown, None) {
                log.error(format!("Action shutdown command failed: {e}"));
            }
        }
    }

    #[cfg(test)]
    pub fn active_rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Runs a server command, as `user` when one is given. Its output is
    /// logged.
    pub fn execute_command(&self, cmd: &str, user: &str, log: &Logger) -> Result<()> {
        let result = run_command(server_command(cmd, user), Some(SERVER_COMMAND_TIMEOUT));
        let output = match &result {
            Ok(out) => out.as_str(),
            Err(e) => e.output.as_str(),
        };
        if !output.trim().is_empty() {
            log.info(format!("Command output: {}", output.trim()));
        }
        result.map(|_| ()).map_err(|e| anyhow!(e.status))
    }
}

fn during(why: &str) -> &'static str {
    if why.is_empty() {
        ""
    } else {
        " during shutdown"
    }
}

/// Rules are identified by allow IP, protocol and port.
fn rule_key(ctx: &TemplateContext) -> String {
    format!("{}/{}/{}", ctx.source_ip, ctx.proto, ctx.port)
}

/// The command for a server command. With a user it runs through `su`,
/// with the command as a single argument, so it runs only as that user
/// (`su <user> -c <cmd>` works with both Linux and macOS `su`).
pub fn server_command(cmd: &str, user: &str) -> Command {
    if user.is_empty() {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(cmd);
        c
    } else {
        let mut c = Command::new("su");
        c.arg(user).arg("-c").arg(cmd);
        c
    }
}

/// Why a command failed, with what it printed.
#[derive(Debug)]
pub struct CommandError {
    /// `exit status 1`, `signal: killed`, or why it could not start.
    pub status: String,
    pub output: String,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.output.trim().is_empty() {
            f.write_str(&self.status)
        } else {
            write!(f, "{}: {}", self.status, self.output.trim())
        }
    }
}

/// Runs `cmd` with `/bin/sh -c`, returning its combined stdout and stderr.
pub fn run_shell(cmd: &str, timeout: Option<Duration>) -> Result<String, CommandError> {
    let mut c = Command::new("/bin/sh");
    c.arg("-c").arg(cmd);
    run_command(c, timeout)
}

/// Runs a command with stdout and stderr captured together (like Go's
/// `CombinedOutput`), killing it after `timeout`.
pub fn run_command(mut cmd: Command, timeout: Option<Duration>) -> Result<String, CommandError> {
    let start_err = |e: std::io::Error| CommandError {
        status: e.to_string(),
        output: String::new(),
    };
    let (mut reader, writer) = std::io::pipe().map_err(start_err)?;
    cmd.stdin(Stdio::null())
        .stdout(writer.try_clone().map_err(start_err)?)
        .stderr(writer);
    let mut child = cmd.spawn().map_err(start_err)?;
    // Drop our copies of the write end so the reader sees end of file.
    drop(cmd);

    let collector = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        buf
    });

    let status = match timeout {
        None => child.wait(),
        Some(limit) => wait_with_timeout(&mut child, limit),
    }
    .map_err(start_err)?;

    // A killed command's children may still hold the pipe open; don't wait
    // for them forever.
    let output = join_with_timeout(collector, Duration::from_secs(2));
    let output = String::from_utf8_lossy(&output).into_owned();

    if status.success() {
        Ok(output)
    } else {
        Err(CommandError {
            status: go_exit_status(&status),
            output,
        })
    }
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    limit: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn join_with_timeout(handle: std::thread::JoinHandle<Vec<u8>>, limit: Duration) -> Vec<u8> {
    let deadline = Instant::now() + limit;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Vec::new();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    handle.join().unwrap_or_default()
}

/// Describes an exit status the way Go's `exec.ExitError` does.
fn go_exit_status(status: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        return format!("exit status {code}");
    }
    match status.signal() {
        Some(libc::SIGKILL) => "signal: killed".into(),
        Some(libc::SIGTERM) => "signal: terminated".into(),
        Some(sig) => format!("signal: {sig}"),
        None => status.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(ip: &str) -> TemplateContext {
        TemplateContext {
            source_ip: ip.into(),
            proto: "tcp".into(),
            port: "22".into(),
            username: "test".into(),
            timestamp: 0,
            timeout: 30,
            access_msg: format!("{ip},tcp/22"),
            nat_access: String::new(),
        }
    }

    fn actions(cfg: ActionsConfig) -> Actions {
        Actions::new(cfg).unwrap()
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn parses_templates() {
        let a = actions(ActionsConfig {
            check: "iptables -C INPUT -s {{.SourceIP}} -j ACCEPT".into(),
            open: "iptables -A INPUT -s {{.SourceIP}} -j ACCEPT".into(),
            close: "iptables -D INPUT -s {{.SourceIP}} -j ACCEPT".into(),
            ..ActionsConfig::default()
        });
        assert!(a.check.is_some() && a.open.is_some() && a.close.is_some());
        let empty = actions(ActionsConfig::default());
        assert!(empty.check.is_none() && empty.open.is_none() && empty.close.is_none());
    }

    #[test]
    fn invalid_template_is_an_error() {
        let err = Actions::new(ActionsConfig {
            open: "{{.Invalid".into(),
            ..ActionsConfig::default()
        })
        .unwrap_err();
        assert!(
            err.to_string().starts_with("parsing open template"),
            "{err}"
        );
        assert!(
            Actions::new(ActionsConfig {
                close: "{{.Typo}}".into(),
                ..ActionsConfig::default()
            })
            .is_err()
        );
    }

    #[test]
    fn validate_and_init() {
        let log = Logger::capture();
        let ok = actions(ActionsConfig {
            validate: "true".into(),
            init: "true".into(),
            ..ActionsConfig::default()
        });
        ok.validate(&log).unwrap();
        ok.init(&log).unwrap();
        let bad = actions(ActionsConfig {
            validate: "echo missing >&2; false".into(),
            init: "exit 3".into(),
            ..ActionsConfig::default()
        });
        let err = bad.validate(&log).unwrap_err().to_string();
        assert_eq!(err, "action validate failed: exit status 1: missing");
        assert_eq!(
            bad.init(&log).unwrap_err().to_string(),
            "action init failed: exit status 3"
        );
        actions(ActionsConfig::default()).validate(&log).unwrap();
    }

    #[test]
    fn open_rule_runs_open_with_placeholders() {
        let dir = tempfile::tempdir().unwrap();
        let open_log = dir.path().join("open.log");
        let mut a = actions(ActionsConfig {
            open: format!(
                "echo {{{{.SourceIP}}}} {{{{.Proto}}}} {{{{.Port}}}} >> {}",
                open_log.display()
            ),
            close: format!(
                "echo close {{{{.SourceIP}}}} >> {}",
                dir.path().join("close.log").display()
            ),
            ..ActionsConfig::default()
        });
        let log = Logger::capture();
        a.open_rule(ctx("10.0.0.1"), Instant::now(), &log).unwrap();
        assert_eq!(read(&open_log).trim(), "10.0.0.1 tcp 22");
        assert_eq!(a.active_rule_count(), 1);
        assert!(log.contains("Opened action rule for 10.0.0.1/tcp/22 (timeout: 30s)"));
    }

    #[test]
    fn check_success_skips_open() {
        let dir = tempfile::tempdir().unwrap();
        let open_log = dir.path().join("open.log");
        let mut a = actions(ActionsConfig {
            check: "true".into(),
            open: format!("echo opened >> {}", open_log.display()),
            close: "true".into(),
            ..ActionsConfig::default()
        });
        a.open_rule(ctx("10.0.0.1"), Instant::now(), &Logger::capture())
            .unwrap();
        assert!(
            !open_log.exists(),
            "open must not run when check says the rule exists"
        );
        assert_eq!(a.active_rule_count(), 1, "an existing rule is taken over");
    }

    #[test]
    fn check_failure_runs_open() {
        let dir = tempfile::tempdir().unwrap();
        let open_log = dir.path().join("open.log");
        let mut a = actions(ActionsConfig {
            check: "false".into(),
            open: format!("echo opened >> {}", open_log.display()),
            close: "true".into(),
            ..ActionsConfig::default()
        });
        a.open_rule(ctx("10.0.0.1"), Instant::now(), &Logger::capture())
            .unwrap();
        assert_eq!(read(&open_log).trim(), "opened");
    }

    #[test]
    fn failed_open_is_not_tracked() {
        let mut a = actions(ActionsConfig {
            open: "false".into(),
            ..ActionsConfig::default()
        });
        let err = a
            .open_rule(ctx("10.0.0.1"), Instant::now(), &Logger::capture())
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("open command failed for 10.0.0.1/tcp/22"),
            "{err}"
        );
        assert_eq!(a.active_rule_count(), 0);
    }

    #[test]
    fn second_knock_refreshes_without_reopening() {
        // fwknop-go ran open again here when no check action was configured,
        // leaving a duplicate firewall rule that was never closed.
        let dir = tempfile::tempdir().unwrap();
        let open_log = dir.path().join("open.log");
        let mut a = actions(ActionsConfig {
            open: format!("echo opened >> {}", open_log.display()),
            close: "true".into(),
            ..ActionsConfig::default()
        });
        let log = Logger::capture();
        let t0 = Instant::now();
        a.open_rule(ctx("10.0.0.1"), t0, &log).unwrap();
        let mut shorter = ctx("10.0.0.1");
        shorter.timeout = 5;
        a.open_rule(shorter, t0 + Duration::from_secs(1), &log)
            .unwrap();
        assert_eq!(read(&open_log), "opened\n");
        assert_eq!(a.active_rule_count(), 1);
        // The latest knock's timeout wins, even when shorter.
        assert_eq!(a.next_expiry(), Some(t0 + Duration::from_secs(6)));
    }

    #[test]
    fn expired_rules_are_closed() {
        let dir = tempfile::tempdir().unwrap();
        let close_log = dir.path().join("close.log");
        let mut a = actions(ActionsConfig {
            open: "true".into(),
            close: format!("echo close {{{{.SourceIP}}}} >> {}", close_log.display()),
            ..ActionsConfig::default()
        });
        let log = Logger::capture();
        let t0 = Instant::now();
        a.open_rule(ctx("10.0.0.1"), t0, &log).unwrap();
        let mut later = ctx("10.0.0.2");
        later.timeout = 60;
        a.open_rule(later, t0, &log).unwrap();

        a.close_expired(t0 + Duration::from_secs(29), &log);
        assert_eq!(a.active_rule_count(), 2);
        a.close_expired(t0 + Duration::from_secs(30), &log);
        assert_eq!(a.active_rule_count(), 1);
        assert_eq!(read(&close_log), "close 10.0.0.1\n");
        assert!(log.contains("Closed action rule for 10.0.0.1/tcp/22"));
        assert_eq!(a.next_expiry(), Some(t0 + Duration::from_secs(60)));
    }

    #[test]
    fn failed_close_is_logged_and_dropped() {
        let mut a = actions(ActionsConfig {
            close: "echo nope >&2; exit 2".into(),
            ..ActionsConfig::default()
        });
        let log = Logger::capture();
        let t0 = Instant::now();
        a.open_rule(ctx("10.0.0.1"), t0, &log).unwrap();
        a.close_expired(t0 + Duration::from_secs(31), &log);
        assert_eq!(a.active_rule_count(), 0);
        assert!(log.contains("Close command failed for 10.0.0.1/tcp/22: exit status 2: nope"));
    }

    #[test]
    fn shutdown_closes_all_rules() {
        let dir = tempfile::tempdir().unwrap();
        let close_log = dir.path().join("close.log");
        let shutdown_log = dir.path().join("shutdown.log");
        let mut a = actions(ActionsConfig {
            open: "true".into(),
            close: format!("echo close {{{{.SourceIP}}}} >> {}", close_log.display()),
            shutdown: format!("echo shutdown >> {}", shutdown_log.display()),
            ..ActionsConfig::default()
        });
        let log = Logger::capture();
        a.open_rule(ctx("10.0.0.1"), Instant::now(), &log).unwrap();
        a.open_rule(ctx("10.0.0.2"), Instant::now(), &log).unwrap();
        assert_eq!(a.active_rule_count(), 2);
        a.shutdown(&log);
        assert_eq!(a.active_rule_count(), 0);
        let closed = read(&close_log);
        assert!(closed.contains("close 10.0.0.1") && closed.contains("close 10.0.0.2"));
        assert_eq!(read(&shutdown_log).trim(), "shutdown");
        assert!(log.contains("Closed action rule for 10.0.0.1/tcp/22 (shutdown)"));
    }

    #[test]
    fn execute_command() {
        let a = actions(ActionsConfig::default());
        let log = Logger::capture();
        a.execute_command("echo hello", "", &log).unwrap();
        assert!(log.contains("Command output: hello"));
        assert_eq!(
            a.execute_command("false", "", &log)
                .unwrap_err()
                .to_string(),
            "exit status 1"
        );
    }

    #[test]
    fn server_command_with_user_passes_the_command_as_one_argument() {
        let c = server_command("id; echo 'x'", "alice");
        assert_eq!(c.get_program(), "su");
        let args: Vec<_> = c.get_args().collect();
        assert_eq!(args, ["alice", "-c", "id; echo 'x'"]);
        let c = server_command("uptime", "");
        assert_eq!(c.get_program(), "/bin/sh");
        assert_eq!(c.get_args().collect::<Vec<_>>(), ["-c", "uptime"]);
    }

    #[test]
    fn commands_time_out() {
        let start = Instant::now();
        let err = run_shell("sleep 5", Some(Duration::from_millis(200))).unwrap_err();
        assert_eq!(err.status, "signal: killed");
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn output_is_combined() {
        assert_eq!(
            run_shell("echo out; echo err >&2", None).unwrap(),
            "out\nerr\n"
        );
    }

    #[test]
    fn templates_load_and_merge() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("t.yaml"),
            "validate: \"which true\"\nopen: \"open {{.SourceIP}}\"\nclose: \"close {{.SourceIP}}\"\n",
        )
        .unwrap();
        let by_name = load_action_template("t.yaml", dir.path().to_str().unwrap()).unwrap();
        assert_eq!(by_name.validate, "which true");
        let by_path =
            load_action_template(dir.path().join("t.yaml").to_str().unwrap(), "/nonexistent")
                .unwrap();
        assert_eq!(by_path, by_name);
        assert_eq!(
            load_action_template("", "/x").unwrap(),
            ActionsConfig::default()
        );
        let err = load_action_template("missing.yaml", dir.path().to_str().unwrap()).unwrap_err();
        assert!(
            err.to_string().starts_with("reading action template"),
            "{err}"
        );

        let inline = ActionsConfig {
            open: "inline open".into(),
            ..ActionsConfig::default()
        };
        let merged = by_name.merged_with(&inline);
        assert_eq!(merged.open, "inline open");
        assert_eq!(merged.close, "close {{.SourceIP}}");
        assert_eq!(merged.validate, "which true");
        assert_eq!(by_name.merged_with(&ActionsConfig::default()), by_name);
    }

    #[test]
    fn shipped_action_templates_parse() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conf_files/actions");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return; // copied in with the packaging milestone
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let cfg = load_action_template(path.to_str().unwrap(), "").unwrap();
            Actions::new(cfg).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
}
