//! Detaching from the terminal.

use std::fs::OpenOptions;

use anyhow::{Context, Result};
use nix::unistd::{ForkResult, chdir, dup2_stderr, dup2_stdin, dup2_stdout, fork, setsid};

/// Moves the process into the background: fork, start a new session, fork
/// again so it can never reacquire a terminal, `chdir /`, and point stdin,
/// stdout and stderr at `/dev/null`. Only the final process returns.
///
/// Must be called before any threads or async runtime are started.
pub fn daemonize() -> Result<()> {
    fork_and_exit_parent()?;
    setsid().context("setsid")?;
    fork_and_exit_parent()?;
    chdir("/").context("chdir /")?;
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("opening /dev/null")?;
    dup2_stdin(&null).context("redirecting stdin")?;
    dup2_stdout(&null).context("redirecting stdout")?;
    dup2_stderr(&null).context("redirecting stderr")?;
    Ok(())
}

fn fork_and_exit_parent() -> Result<()> {
    // SAFETY: the server has not started any threads yet, so the child
    // is a complete copy of the only thread.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Parent { .. } => {
            // Leave without running destructors or flushing buffers the
            // child also holds.
            // SAFETY: _exit is async-signal-safe and ends the process.
            unsafe { libc::_exit(0) }
        }
        ForkResult::Child => Ok(()),
    }
}
