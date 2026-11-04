//! The server: one event loop that owns every piece of state and handles
//! SPA packets, rule expiries and signals one at a time.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use tokio::signal::unix::{SignalKind, signal};

use fkospa::{DigestType, Request, SpaData, SpaMessage};

use crate::access::{AccessStanza, load_access_config};
use crate::actions::{Actions, load_action_template};
use crate::cli::Cli;
use crate::config::{ServerConfig, load_server_config};
use crate::log::Logger;
use crate::replay::ReplayCache;
use crate::template::TemplateContext;

/// Datagrams longer than this are truncated (and so fail to decrypt).
pub const MAX_SPA_PACKET_SIZE: usize = 1500;

/// Everything loaded from the config files, ready to run.
#[derive(Debug)]
pub struct Loaded {
    pub cfg: ServerConfig,
    pub stanzas: Vec<AccessStanza>,
    pub actions: Actions,
}

/// Loads the server config and access stanzas.
pub fn load_config_and_access(cli: &Cli) -> Result<(ServerConfig, Vec<AccessStanza>)> {
    let cfg = load_server_config(cli, std::env::vars_os())?;
    let stanzas = load_access_config(&cfg.access_file)?;
    Ok((cfg, stanzas))
}

/// Builds the actions: the action template, if any, with inline actions
/// overriding it one action at a time.
pub fn build_actions(cfg: &ServerConfig) -> Result<Actions> {
    let mut actions = cfg.actions.clone();
    if !cfg.action_template.is_empty() {
        actions =
            load_action_template(&cfg.action_template, &cfg.action_dir)?.merged_with(&cfg.actions);
    }
    Actions::new(actions).context("actions config")
}

pub fn load(cli: &Cli) -> Result<Loaded> {
    let (cfg, stanzas) = load_config_and_access(cli)?;
    let actions = build_actions(&cfg)?;
    Ok(Loaded {
        cfg,
        stanzas,
        actions,
    })
}

pub fn new_logger(cfg: &ServerConfig) -> Result<Logger> {
    Logger::new(
        &cfg.log_file,
        &cfg.syslog_identity,
        &cfg.syslog_facility,
        cfg.verbose,
        cfg.foreground,
    )
}

#[derive(Debug)]
pub struct Server {
    pub cfg: ServerConfig,
    pub stanzas: Vec<AccessStanza>,
    pub replay: ReplayCache,
    pub actions: Actions,
    pub log: Logger,
}

/// How the event loop ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// SIGTERM or SIGINT: rules closed, shutdown action run.
    Signal,
}

impl Server {
    pub fn new(loaded: Loaded, log: Logger) -> Server {
        let replay = ReplayCache::new(ReplayCache::ttl_for_max_age(loaded.cfg.max_spa_packet_age));
        Server {
            cfg: loaded.cfg,
            stanzas: loaded.stanzas,
            replay,
            actions: loaded.actions,
            log,
        }
    }

    /// Runs until SIGTERM or SIGINT. SIGHUP restarts with fresh config.
    pub async fn run(mut self, socket: std::net::UdpSocket, cli: &Cli) -> Result<Exit> {
        let mut socket = tokio::net::UdpSocket::from_std(socket)?;
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sighup = signal(SignalKind::hangup())?;
        let mut buf = vec![0u8; MAX_SPA_PACKET_SIZE];

        loop {
            let next_expiry = self.actions.next_expiry();
            let expiry = async {
                match next_expiry {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = sigterm.recv() => return Ok(self.stop("terminated")),
                _ = sigint.recv() => return Ok(self.stop("interrupt")),
                _ = sighup.recv() => {
                    if let Some(new_socket) = self.restart(cli, &socket)? {
                        socket = tokio::net::UdpSocket::from_std(new_socket)?;
                    }
                }
                () = expiry => self.actions.close_expired(Instant::now(), &self.log),
                received = socket.recv_from(&mut buf) => match received {
                    Ok((n, from)) => self.process_packet(&buf[..n], from.ip(), Instant::now(), wall_clock_ns()),
                    Err(e) => self.log.error(format!("UDP read error: {e}")),
                },
            }
        }
    }

    fn stop(&mut self, signal_name: &str) -> Exit {
        self.log
            .info(format!("Received signal {signal_name}, shutting down..."));
        self.actions.shutdown(&self.log);
        Exit::Signal
    }

    /// SIGHUP: re-read everything. If the new configuration does not load
    /// (or its validate action fails, or its socket cannot be bound), keep
    /// running on the old one. Otherwise close every rule, run the old
    /// shutdown action and start again on the new configuration. The replay
    /// cache is kept.
    ///
    /// Returns the new socket when the listen address changed. An error
    /// (the new init action failing) stops the server.
    fn restart(
        &mut self,
        cli: &Cli,
        current: &tokio::net::UdpSocket,
    ) -> Result<Option<std::net::UdpSocket>> {
        self.log.info("Received signal hangup, restarting...");
        let candidate = match self.load_for_restart(cli, current) {
            Ok(c) => c,
            Err(e) => {
                self.log.error(format!(
                    "Restart failed, keeping the current configuration: {e:#}"
                ));
                return Ok(None);
            }
        };
        let (loaded, log, new_socket) = candidate;

        self.actions.shutdown(&self.log);
        self.replay
            .set_ttl(ReplayCache::ttl_for_max_age(loaded.cfg.max_spa_packet_age));
        self.cfg = loaded.cfg;
        self.stanzas = loaded.stanzas;
        self.actions = loaded.actions;
        self.log = log;

        if let Err(e) = self.actions.init(&self.log) {
            self.log.error(format!("Restart failed: {e}"));
            return Err(e);
        }
        self.log.info(format!(
            "Restarted: loaded {} access stanza(s) from {}",
            self.stanzas.len(),
            self.cfg.access_file
        ));
        if self.cfg.test {
            self.log
                .info("Running in test mode — no actions will be taken.");
        }
        if new_socket.is_some() {
            self.log.info(format!(
                "UDP server listening on {}",
                join_host_port(&self.cfg.bind_address, self.cfg.udp_port)
            ));
        }
        Ok(new_socket)
    }

    #[allow(clippy::type_complexity)]
    fn load_for_restart(
        &self,
        cli: &Cli,
        current: &tokio::net::UdpSocket,
    ) -> Result<(Loaded, Logger, Option<std::net::UdpSocket>)> {
        let loaded = load(cli)?;
        let log = new_logger(&loaded.cfg)?;
        loaded.actions.validate(&log)?;
        let same_address = loaded.cfg.bind_address == self.cfg.bind_address
            && loaded.cfg.udp_port == self.cfg.udp_port;
        let new_socket = if same_address && current.local_addr().is_ok() {
            None
        } else {
            Some(bind_udp(&loaded.cfg.bind_address, loaded.cfg.udp_port)?)
        };
        Ok((loaded, log, new_socket))
    }

    /// Tries each access stanza whose source matches the packet source;
    /// the first one whose key set decrypts the packet decides its fate.
    pub fn process_packet(&mut self, data: &[u8], src: IpAddr, now: Instant, wall_ns: i128) {
        let src = src.to_canonical();
        let Server {
            cfg,
            stanzas,
            replay,
            actions,
            log,
        } = self;
        log.debug(format!(
            "Received UDP datagram ({} bytes) from {src}",
            data.len()
        ));
        replay.purge(now);
        let spa = SpaData::from_bytes(data);

        for (i, stanza) in stanzas.iter().enumerate() {
            let n = i + 1;
            if !stanza.matches_source(src) {
                continue;
            }
            log.debug(format!(
                "Trying access stanza #{n} (source: {})",
                stanza.raw.source
            ));
            let msg = match SpaMessage::decrypt(&spa, &stanza.keys) {
                Ok(m) => m,
                Err(e) => {
                    log.debug(format!("Access stanza #{n} decrypt failed: {e}"));
                    continue;
                }
            };
            log.info(format!(
                "(access stanza #{n}) SPA packet from {src} decrypted successfully"
            ));

            // Future timestamps are held to the same window, otherwise a
            // packet could outlive its replay digest.
            if cfg.max_spa_packet_age > 0 {
                let age_ns = wall_ns - i128::from(msg.timestamp) * NS;
                let max_ns = i128::from(cfg.max_spa_packet_age) * NS;
                if age_ns > max_ns {
                    log.warn(format!(
                        "SPA packet from {src} is too old (age: {}, max: {}s)",
                        go_duration(round_secs(age_ns)),
                        cfg.max_spa_packet_age
                    ));
                    return;
                }
                if -age_ns > max_ns {
                    log.warn(format!(
                        "SPA packet from {src} is timestamped in the future (by {}, max: {}s)",
                        go_duration(round_secs(-age_ns)),
                        cfg.max_spa_packet_age
                    ));
                    return;
                }
            }

            let digest = DigestType::Sha256.digest_b64(data);
            if replay.is_duplicate(&digest, now) {
                log.warn(format!("Replay detected from {src} (digest: {digest})"));
                return;
            }
            replay.add(digest, now);

            let required = &stanza.raw.require_username;
            if !required.is_empty() && msg.username != *required {
                log.warn(format!(
                    "Username mismatch: got {:?}, required {:?}",
                    msg.username, required
                ));
                return;
            }

            if stanza.raw.require_source_address {
                let text = msg.request.message_text();
                if text.is_empty() || !contains_ip(&text, src) {
                    log.warn(format!(
                        "Source address mismatch: SPA from {src} but access msg is {text:?}"
                    ));
                    return;
                }
            }

            log_spa_message(log, &msg, src, n);

            if cfg.test {
                log.info(format!(
                    "(access stanza #{n}) --test mode enabled, skipping action."
                ));
                return;
            }

            dispatch(actions, log, &msg, stanza, src, n, now);
            return;
        }

        log.warn(format!(
            "No matching access stanza for SPA packet from {src}"
        ));
    }
}

const NS: i128 = 1_000_000_000;

/// Runs the server command, or opens the rule, a validated SPA message
/// asks for.
fn dispatch(
    actions: &mut Actions,
    log: &Logger,
    msg: &SpaMessage,
    stanza: &AccessStanza,
    src: IpAddr,
    n: usize,
    now: Instant,
) {
    if let Request::Command(cmd) = &msg.request {
        if !stanza.raw.enable_cmd_exec {
            log.warn(format!(
                "(access stanza #{n}) CommandMsg from {src} but enable_cmd_exec is false"
            ));
            return;
        }
        log.info(format!("(access stanza #{n}) Executing command from {src}"));
        if let Err(e) = actions.execute_command(cmd, &stanza.raw.cmd_exec_user, log) {
            log.error(format!(
                "(access stanza #{n}) Command execution failed: {e}"
            ));
        }
        return;
    }

    let Some(ctx) = template_context(msg, src, stanza) else {
        return;
    };
    if !stanza.allows_port(&ctx.proto, &ctx.port) {
        log.warn(format!(
            "(access stanza #{n}) Port {}/{} not allowed by open_ports",
            ctx.proto, ctx.port
        ));
        return;
    }
    if let Err(e) = actions.open_rule(ctx, now, log) {
        log.error(format!(
            "(access stanza #{n}) Failed to open access rule: {e:#}"
        ));
    }
}

/// The placeholder values for an access request. The allow IP `0.0.0.0` or
/// `::` becomes the packet source.
pub fn template_context(
    msg: &SpaMessage,
    src: IpAddr,
    stanza: &AccessStanza,
) -> Option<TemplateContext> {
    let access = msg.request.access_message()?;
    let source_ip = if access.allow_ip.to_canonical().is_unspecified() {
        src.to_canonical().to_string()
    } else {
        access.allow_ip.to_string()
    };
    Some(TemplateContext {
        source_ip,
        proto: access.spec.proto.to_string(),
        port: access.spec.port.to_string(),
        username: msg.username.clone(),
        timestamp: msg.timestamp,
        timeout: effective_timeout(msg, stanza),
        access_msg: msg.request.message_text(),
        nat_access: msg.request.nat_access().unwrap_or("").to_string(),
    })
}

/// The client timeout, capped by the max access timeout; or the access
/// timeout when the client asked for none.
pub fn effective_timeout(msg: &SpaMessage, stanza: &AccessStanza) -> i64 {
    match msg.request.client_timeout() {
        Some(t) => {
            let t = i64::from(t.get());
            if stanza.max_access_timeout > 0 && t > stanza.max_access_timeout {
                stanza.max_access_timeout
            } else {
                t
            }
        }
        None => stanza.access_timeout,
    }
}

/// Whether the IP before the first `,` in an access message is `ip`.
pub fn contains_ip(message: &str, ip: IpAddr) -> bool {
    let msg_ip = message.split(',').next().unwrap_or("");
    match msg_ip.parse::<IpAddr>() {
        Ok(parsed) => parsed.to_canonical() == ip.to_canonical(),
        Err(_) => msg_ip == ip.to_string(),
    }
}

fn log_spa_message(log: &Logger, msg: &SpaMessage, src: IpAddr, n: usize) {
    log.info(format!(
        "SPA Field Values (access stanza #{n}, from {src}):"
    ));
    log.info(format!("  Random Value: {}", msg.rand_val));
    log.info(format!("  Username:     {}", msg.username));
    log.info(format!(
        "  Timestamp:    {} ({})",
        cli_common::time::rfc3339_local(msg.timestamp),
        msg.timestamp
    ));
    log.info(format!("  Message Type: {}", msg.message_type()));
    log.info(format!("  Access:       {}", msg.request.message_text()));
    if let Some(nat) = msg.request.nat_access() {
        log.info(format!("  NAT Access:   {nat}"));
    }
    if let Some(auth) = &msg.server_auth {
        log.info(format!("  Server Auth:  {auth}"));
    }
    if let Some(t) = msg.request.client_timeout() {
        log.info(format!("  Timeout:      {t}s"));
    }
    log.info(format!("  Digest Type:  {}", msg.digest_type));
}

/// Nanoseconds to whole seconds, rounding half away from zero (Go's
/// `Duration.Round(time.Second)`).
fn round_secs(ns: i128) -> i64 {
    let rounded = if ns >= 0 {
        (ns + NS / 2) / NS
    } else {
        (ns - NS / 2) / NS
    };
    i64::try_from(rounded).unwrap_or(i64::MAX)
}

/// Whole seconds formatted like Go's `Duration.String`: `45s`, `2m0s`,
/// `1h0m5s`.
pub fn go_duration(secs: i64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let sign = if secs < 0 { "-" } else { "" };
    let s = secs.unsigned_abs();
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{sign}{h}h{m}m{sec}s")
    } else if m > 0 {
        format!("{sign}{m}m{sec}s")
    } else {
        format!("{sign}{sec}s")
    }
}

pub fn wall_clock_ns() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

pub fn join_host_port(host: &str, port: i64) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Binds the server's UDP socket. For the wildcard addresses `0.0.0.0` and
/// `::` it listens on IPv4 and IPv6 at once (one dual-stack socket), as
/// fwknop-go does.
pub fn bind_udp(bind_address: &str, port: i64) -> Result<std::net::UdpSocket> {
    let text = join_host_port(bind_address, port);
    let port =
        u16::try_from(port).map_err(|_| anyhow!("resolving UDP address {text}: invalid port"))?;
    let ip = resolve_bind_ip(bind_address, port)
        .map_err(|e| anyhow!("resolving UDP address {text}: {e}"))?;
    let socket = if ip.is_unspecified() {
        bind_dual_stack(port).or_else(|_| std::net::UdpSocket::bind(SocketAddr::new(ip, port)))
    } else {
        std::net::UdpSocket::bind(SocketAddr::new(ip, port))
    }
    .map_err(|e| anyhow!("listening on UDP {text}: {e}"))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn resolve_bind_ip(host: &str, port: u16) -> std::io::Result<IpAddr> {
    if host.is_empty() {
        return Ok(IpAddr::from([0, 0, 0, 0]));
    }
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .map(|a| a.ip())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses"))
}

fn bind_dual_stack(port: u16) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::new(IpAddr::from([0u16; 8]), port).into())?;
    Ok(socket.into())
}
