//! fwknopd's log: stderr in the foreground; the log file and syslog in the
//! background. Lines look like fwknop-go's: `2026/11/04 14:57:31 [INFO] msg`.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Warn,
    Error,
    Debug,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Info => "[INFO]",
            Level::Warn => "[WARN]",
            Level::Error => "[ERROR]",
            Level::Debug => "[DEBUG]",
        }
    }

    fn syslog_priority(self) -> libc::c_int {
        match self {
            Level::Info => libc::LOG_INFO,
            Level::Warn => libc::LOG_WARNING,
            Level::Error => libc::LOG_ERR,
            Level::Debug => libc::LOG_DEBUG,
        }
    }

    /// The text prefix fwknop-go put on syslog messages, kept so existing
    /// log searches still match.
    fn syslog_prefix(self) -> &'static str {
        match self {
            Level::Warn => "WARNING: ",
            Level::Error => "ERROR: ",
            _ => "",
        }
    }
}

#[derive(Debug, Default)]
pub struct Logger {
    file: Option<Mutex<File>>,
    stderr: bool,
    syslog: bool,
    verbose: bool,
    /// Test capture of every line, debug included.
    captured: Option<Arc<Mutex<Vec<String>>>>,
}

impl Logger {
    /// The server's logger. In the foreground everything goes to stderr;
    /// otherwise to `log_file` (if set) and syslog (if `syslog_ident` is
    /// set). A syslog failure is not fatal.
    pub fn new(
        log_file: &str,
        syslog_ident: &str,
        syslog_facility: &str,
        verbose: bool,
        foreground: bool,
    ) -> Result<Logger> {
        let mut logger = Logger {
            verbose,
            ..Logger::default()
        };
        if foreground {
            logger.stderr = true;
            return Ok(logger);
        }
        if !log_file.is_empty() {
            let path = Path::new(log_file);
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o750)
                    .create(dir)
                    .map_err(|e| anyhow!("creating log directory {}: {e}", dir.display()))?;
            }
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o640)
                .open(path)
                .map_err(|e| anyhow!("opening log file {log_file}: {e}"))?;
            logger.file = Some(Mutex::new(file));
        }
        if !syslog_ident.is_empty() {
            match open_syslog(syslog_ident, syslog_facility) {
                Ok(()) => logger.syslog = true,
                Err(e) => logger.warn(format!("syslog setup failed: {e}")),
            }
        }
        Ok(logger)
    }

    /// A logger that records lines for tests to inspect.
    #[cfg(test)]
    pub fn capture() -> Logger {
        Logger {
            verbose: true,
            captured: Some(Arc::new(Mutex::new(Vec::new()))),
            ..Logger::default()
        }
    }

    #[cfg(test)]
    pub fn lines(&self) -> Vec<String> {
        self.captured
            .as_ref()
            .map(|c| c.lock().unwrap().clone())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub fn contains(&self, needle: &str) -> bool {
        self.lines().iter().any(|l| l.contains(needle))
    }

    pub fn info(&self, msg: impl AsRef<str>) {
        self.log(Level::Info, msg.as_ref());
    }

    pub fn warn(&self, msg: impl AsRef<str>) {
        self.log(Level::Warn, msg.as_ref());
    }

    pub fn error(&self, msg: impl AsRef<str>) {
        self.log(Level::Error, msg.as_ref());
    }

    /// Logged only in verbose mode, and never to syslog.
    pub fn debug(&self, msg: impl AsRef<str>) {
        self.log(Level::Debug, msg.as_ref());
    }

    fn log(&self, level: Level, msg: &str) {
        if level == Level::Debug && !self.verbose {
            return;
        }
        if let Some(captured) = &self.captured {
            captured
                .lock()
                .unwrap()
                .push(format!("{} {msg}", level.tag()));
        }
        let line = format!(
            "{} {} {msg}\n",
            cli_common::time::log_timestamp_now(),
            level.tag()
        );
        if self.stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        if let Some(file) = &self.file
            && let Ok(mut f) = file.lock()
        {
            let _ = f.write_all(line.as_bytes());
        }
        if self.syslog && level != Level::Debug {
            write_syslog(level, msg);
        }
    }
}

fn facility(name: &str) -> libc::c_int {
    match name {
        "auth" => libc::LOG_AUTH,
        "local0" => libc::LOG_LOCAL0,
        "local1" => libc::LOG_LOCAL1,
        "local2" => libc::LOG_LOCAL2,
        "local3" => libc::LOG_LOCAL3,
        "local4" => libc::LOG_LOCAL4,
        "local5" => libc::LOG_LOCAL5,
        "local6" => libc::LOG_LOCAL6,
        "local7" => libc::LOG_LOCAL7,
        _ => libc::LOG_DAEMON,
    }
}

fn open_syslog(ident: &str, facility_name: &str) -> Result<()> {
    let ident = CString::new(ident).map_err(|_| anyhow!("syslog identity contains a NUL byte"))?;
    // openlog keeps the pointer, so the identity must live for the rest of
    // the process. A restart may leak one more short string.
    let ident: &'static std::ffi::CStr = Box::leak(ident.into_boxed_c_str());
    // SAFETY: `ident` is a valid NUL-terminated string that is never freed.
    unsafe { libc::openlog(ident.as_ptr(), libc::LOG_PID, facility(facility_name)) };
    Ok(())
}

fn write_syslog(level: Level, msg: &str) {
    let text = format!("{}{msg}", level.syslog_prefix()).replace('\0', " ");
    let Ok(text) = CString::new(text) else {
        return;
    };
    // SAFETY: both strings are valid and NUL-terminated; the "%s" format
    // keeps `msg` from being read as a format string.
    unsafe { libc::syslog(level.syslog_priority(), c"%s".as_ptr(), text.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_only_when_verbose() {
        let log = Logger::capture();
        log.debug("seen");
        assert!(log.contains("[DEBUG] seen"));
        let quiet = Logger {
            verbose: false,
            ..Logger::capture()
        };
        quiet.debug("hidden");
        quiet.info("shown");
        assert_eq!(quiet.lines(), ["[INFO] shown"]);
    }

    #[test]
    fn writes_go_style_lines_to_the_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/fwknopd.log");
        let log = Logger::new(path.to_str().unwrap(), "", "daemon", false, false).unwrap();
        log.info("hello");
        log.warn("careful");
        log.error("broken");
        log.debug("not verbose");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].ends_with(" [INFO] hello"), "{}", lines[0]);
        assert!(lines[1].ends_with(" [WARN] careful"));
        assert!(lines[2].ends_with(" [ERROR] broken"));
        assert_eq!(&lines[0][4..5], "/");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn foreground_ignores_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwknopd.log");
        let log = Logger::new(path.to_str().unwrap(), "fwknopd", "daemon", false, true).unwrap();
        log.info("to stderr");
        assert!(!path.exists());
    }

    #[test]
    fn unwritable_log_file_is_an_error() {
        let err =
            Logger::new("/nonexistent-root-dir/x/fwknopd.log", "", "", false, false).unwrap_err();
        assert!(err.to_string().contains("log"), "{err}");
    }

    #[test]
    fn facilities() {
        assert_eq!(facility("auth"), libc::LOG_AUTH);
        assert_eq!(facility("local7"), libc::LOG_LOCAL7);
        assert_eq!(facility("user"), libc::LOG_DAEMON);
        assert_eq!(facility(""), libc::LOG_DAEMON);
    }
}
