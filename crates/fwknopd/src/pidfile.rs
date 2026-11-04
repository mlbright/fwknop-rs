//! The PID file, and `--status`, `--kill` and `--restart`, which use it.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Result, anyhow};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// Reads a PID file: a decimal PID, optionally followed by whitespace.
pub fn read_pid(path: &str) -> Result<Option<i32>, String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    text.trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 0)
        .map(Some)
        .ok_or_else(|| format!("invalid PID file content: {path}"))
}

/// Whether a process with this PID exists (it may belong to another user).
pub fn is_running(pid: i32) -> bool {
    match kill(Pid::from_raw(pid), None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

/// Writes `pid` followed by a newline, creating the directory if needed.
pub fn write_pid(path: &str, pid: u32) -> std::io::Result<()> {
    if let Some(dir) = Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
    {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(dir)?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)?;
    writeln!(f, "{pid}")
}

/// Refuses to start a second server on the same PID file.
pub fn ensure_not_running(path: &str) -> Result<()> {
    if let Ok(Some(pid)) = read_pid(path)
        && is_running(pid)
        && pid != std::process::id() as i32
    {
        return Err(anyhow!(
            "fwknopd is already running (PID {pid}, from {path})"
        ));
    }
    Ok(())
}

/// `--status`.
pub fn status(path: &str, out: &mut dyn Write) -> Result<()> {
    match read_pid(path).map_err(|e| anyhow!(e))? {
        None => writeln!(out, "fwknopd does not appear to be running (no PID file).")?,
        Some(pid) if is_running(pid) => writeln!(out, "fwknopd is running (PID {pid}).")?,
        Some(pid) => writeln!(out, "fwknopd PID {pid} (from {path}) — not running.")?,
    }
    Ok(())
}

/// `--kill` (SIGTERM) and `--restart` (SIGHUP).
pub fn signal_daemon(path: &str, sig: Signal, out: &mut dyn Write) -> Result<()> {
    let text = fs::read_to_string(path).map_err(|e| anyhow!("cannot read PID file {path}: {e}"))?;
    let pid = text
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| anyhow!("invalid PID in {path}"))?;
    kill(Pid::from_raw(pid), sig).map_err(|e| anyhow!("sending signal to PID {pid}: {e}"))?;
    writeln!(
        out,
        "Sent signal {} to fwknopd (PID {pid}).",
        signal_name(sig)
    )?;
    Ok(())
}

/// Signal names as Go prints them (`terminated`, `hangup`, …).
pub fn signal_name(sig: Signal) -> &'static str {
    match sig {
        Signal::SIGTERM => "terminated",
        Signal::SIGHUP => "hangup",
        Signal::SIGINT => "interrupt",
        _ => sig.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid_file(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwknopd.pid");
        fs::write(&path, content).unwrap();
        let p = path.to_str().unwrap().to_string();
        (dir, p)
    }

    #[test]
    fn reads_pids_with_or_without_newline() {
        // fwknop-go dropped the last byte unconditionally, so "1234" read
        // as 123 and an empty file crashed.
        assert_eq!(read_pid(&pid_file("1234\n").1), Ok(Some(1234)));
        assert_eq!(read_pid(&pid_file("1234").1), Ok(Some(1234)));
        assert_eq!(read_pid(&pid_file(" 42 \r\n").1), Ok(Some(42)));
        assert!(read_pid(&pid_file("").1).is_err());
        assert!(read_pid(&pid_file("abc").1).is_err());
        assert!(read_pid(&pid_file("-5").1).is_err());
        assert_eq!(read_pid("/nonexistent/fwknopd.pid"), Ok(None));
    }

    #[test]
    fn status_messages() {
        let mut out = Vec::new();
        status("/nonexistent/fwknopd.pid", &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "fwknopd does not appear to be running (no PID file).\n"
        );

        let me = std::process::id();
        let (_d, path) = pid_file(&format!("{me}\n"));
        let mut out = Vec::new();
        status(&path, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("fwknopd is running (PID {me}).\n")
        );

        let (_d, path) = pid_file("999999\n");
        let mut out = Vec::new();
        status(&path, &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("not running"));

        let (_d, path) = pid_file("");
        assert!(status(&path, &mut Vec::new()).is_err());
    }

    #[test]
    fn write_and_guard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/fwknopd.pid");
        let path = path.to_str().unwrap();
        ensure_not_running(path).unwrap();
        write_pid(path, 999_999).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), "999999\n");
        ensure_not_running(path).unwrap(); // stale PID file

        // Our parent (the test runner) is a live process.
        let parent = nix::unistd::getppid().as_raw() as u32;
        write_pid(path, parent).unwrap();
        let err = ensure_not_running(path).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");
    }

    #[test]
    fn signal_errors() {
        let err = signal_daemon("/nonexistent/fwknopd.pid", Signal::SIGTERM, &mut Vec::new())
            .unwrap_err();
        assert!(err.to_string().starts_with("cannot read PID file"), "{err}");
        let (_d, path) = pid_file("abc");
        let err = signal_daemon(&path, Signal::SIGTERM, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().starts_with("invalid PID in"), "{err}");
    }

    #[test]
    fn signal_names() {
        assert_eq!(signal_name(Signal::SIGTERM), "terminated");
        assert_eq!(signal_name(Signal::SIGHUP), "hangup");
        assert_eq!(signal_name(Signal::SIGINT), "interrupt");
    }
}
