//! `fwknopd`: receives Single Packet Authorization (SPA) packets over UDP,
//! decrypts and checks them against access stanzas, and runs actions to
//! open (and later close) firewall access.

mod access;
mod actions;
mod cli;
mod config;
mod daemon;
mod log;
mod pidfile;
mod replay;
mod server;
mod template;

#[cfg(test)]
mod tests;

use std::io::Write;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use nix::sys::signal::Signal;

use fkospa::PROTOCOL_VERSION;

use crate::access::AccessStanza;
use crate::cli::Cli;
use crate::config::ServerConfig;
use crate::replay::ReplayCache;
use crate::server::{
    Loaded, Server, bind_udp, build_actions, go_duration, join_host_port, new_logger,
};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fwknopd: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let cfg = config::load_server_config(cli, std::env::vars_os())?;
    let info = buildinfo::Info::new(env!("CARGO_PKG_VERSION"));

    if cfg.show_version {
        writeln!(
            out,
            "fwknopd (Rust) version {info} (SPA protocol {PROTOCOL_VERSION})"
        )?;
        return Ok(());
    }
    if cfg.status {
        return pidfile::status(&cfg.pid_file, &mut out);
    }
    if cfg.kill {
        return pidfile::signal_daemon(&cfg.pid_file, Signal::SIGTERM, &mut out);
    }
    if cfg.restart {
        return pidfile::signal_daemon(&cfg.pid_file, Signal::SIGHUP, &mut out);
    }

    let stanzas = access::load_access_config(&cfg.access_file)?;
    if cfg.dump_config {
        dump_config(&mut out, &cfg, &stanzas)?;
        return Ok(());
    }
    drop(out);

    let actions = build_actions(&cfg)?;
    let log = new_logger(&cfg)?;
    log.info(format!("Starting fwknopd (Rust) version {info}"));
    log.info(format!(
        "Loaded {} access stanza(s) from {}",
        stanzas.len(),
        cfg.access_file
    ));
    if !cfg.action_template.is_empty() {
        log.info(format!("Loaded action template: {}", cfg.action_template));
    }
    match ReplayCache::ttl_for_max_age(cfg.max_spa_packet_age) {
        Some(ttl) => log.info(format!(
            "Replay cache initialized (TTL: {})",
            go_duration(ttl.as_secs() as i64)
        )),
        None => log.info("Replay cache initialized (TTL: none, since max_spa_packet_age is 0)"),
    }
    if cfg.enable_digest_persistence {
        log.warn("enable_digest_persistence is not implemented: the replay cache is in memory only and is emptied on restart");
    }

    // Everything that can fail at startup happens before detaching, so the
    // error reaches the terminal and the exit code.
    if !cfg.foreground {
        pidfile::ensure_not_running(&cfg.pid_file)?;
    }
    let socket = bind_udp(&cfg.bind_address, cfg.udp_port)?;
    actions.validate(&log)?;
    actions.init(&log)?;

    let mut wrote_pid = false;
    if !cfg.foreground {
        daemon::daemonize()?;
        match pidfile::write_pid(&cfg.pid_file, std::process::id()) {
            Ok(()) => {
                wrote_pid = true;
                log.info(format!("PID file written: {}", cfg.pid_file));
            }
            Err(e) => log.warn(format!("Failed to write PID file: {e}")),
        }
    }
    if cfg.test {
        log.info("Running in test mode — no actions will be taken.");
    }
    let listening = match socket.local_addr() {
        Ok(addr) if cfg.udp_port == 0 => join_host_port(&cfg.bind_address, i64::from(addr.port())),
        _ => join_host_port(&cfg.bind_address, cfg.udp_port),
    };
    log.info(format!("UDP server listening on {listening}"));

    let pid_file = cfg.pid_file.clone();
    let server = Server::new(
        Loaded {
            cfg,
            stanzas,
            actions,
        },
        log,
    );
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the event loop")?
        .block_on(server.run(socket, cli));
    if wrote_pid {
        let _ = std::fs::remove_file(&pid_file);
    }
    result.map(|_| ())
}

fn dump_config(out: &mut dyn Write, cfg: &ServerConfig, stanzas: &[AccessStanza]) -> Result<()> {
    writeln!(out, "fwknopd configuration:")?;
    writeln!(out, "  Config file:    {}", cfg.config_file)?;
    writeln!(out, "  Access file:    {}", cfg.access_file)?;
    writeln!(out, "  UDP port:       {}", cfg.udp_port)?;
    writeln!(out, "  Bind address:   {}", cfg.bind_address)?;
    writeln!(out, "  Log file:       {}", cfg.log_file)?;
    writeln!(out, "  Syslog ident:   {}", cfg.syslog_identity)?;
    writeln!(out, "  PID file:       {}", cfg.pid_file)?;
    writeln!(out, "  Max packet age: {}s", cfg.max_spa_packet_age)?;
    writeln!(out, "  Verbose:        {}", cfg.verbose)?;
    writeln!(out, "  Test mode:      {}", cfg.test)?;
    writeln!(out)?;
    writeln!(out, "Access stanzas ({}):", stanzas.len())?;
    for (i, s) in stanzas.iter().enumerate() {
        writeln!(out, "  Access stanza #{}:", i + 1)?;
        writeln!(out, "    Source:           {}", s.raw.source)?;
        writeln!(
            out,
            "    Open ports:       [{}]",
            s.raw.open_ports.join(" ")
        )?;
        writeln!(out, "    HMAC digest:      {}", s.raw.hmac_digest_type)?;
        writeln!(out, "    Encryption mode:  {}", s.raw.encryption_mode)?;
        writeln!(out, "    Access timeout:   {}s", s.access_timeout)?;
        writeln!(out, "    Require username: {}", s.raw.require_username)?;
        writeln!(
            out,
            "    Require src addr: {}",
            s.raw.require_source_address
        )?;
        writeln!(
            out,
            "    Enc key length:   {} bytes",
            s.keys.encryption_key.len()
        )?;
        writeln!(
            out,
            "    HMAC key length:  {} bytes",
            s.keys.hmac.as_ref().map_or(0, |h| h.len())
        )?;
    }
    Ok(())
}
