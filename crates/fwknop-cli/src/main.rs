//! `fwknop`: sends Single Packet Authorization (SPA) requests to an fwknopd
//! server to ask for access to services behind its firewall.

mod cli;
mod config;
mod duration;
mod rcfile;
mod resolve;

use std::io::Write;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;

use fkospa::{
    AccessMessage, DigestType, EncryptionMode, HmacKey, HmacType, KeySet, PROTOCOL_VERSION,
    Request, SpaMessage,
};

use crate::cli::Cli;
use crate::config::{ClientConfig, default_rc_path, load_config};

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
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    match run(
        &cli,
        std::env::vars_os(),
        &mut stdout.lock(),
        &mut stderr.lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fwknop: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Runs the client. Results (version, keys, rc stanza names, SPA data in
/// test mode) go to `out`; verbose details go to `err`.
pub fn run<I, K, V>(cli: &Cli, env: I, out: &mut dyn Write, err: &mut dyn Write) -> Result<()>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = env
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
        .collect();
    let cfg = load_config(cli, env.iter().map(|(k, v)| (k, v)))?;

    if cfg.show_version {
        let info = buildinfo::Info::new(env!("CARGO_PKG_VERSION"));
        writeln!(
            out,
            "fwknop (Rust) version {info} (SPA protocol {PROTOCOL_VERSION})"
        )?;
        return Ok(());
    }
    if cfg.key_gen {
        writeln!(
            out,
            "KEY_BASE64: {}",
            fkospa::generate_key(32).context("generating encryption key")?
        )?;
        writeln!(
            out,
            "HMAC_KEY_BASE64: {}",
            fkospa::generate_key(32).context("generating HMAC key")?
        )?;
        return Ok(());
    }
    if cfg.stanza_list {
        let path = if cfg.rc_file.is_empty() {
            default_rc_path(&env).unwrap_or_else(|| PathBuf::from(".fwknoprc"))
        } else {
            PathBuf::from(&cfg.rc_file)
        };
        for name in rcfile::list_stanzas(&path)? {
            writeln!(out, "{name}")?;
        }
        return Ok(());
    }

    if cfg.destination.is_empty() {
        bail!("destination is required (use -D/--destination)");
    }
    if cfg.access.is_empty() && cfg.server_cmd.is_empty() {
        bail!("access specification is required (use -A/--access)");
    }

    // Same order of checks as fwknop-go, so the first error reported for a
    // bad command line is the same.
    let allow_ip = if cfg.server_cmd.is_empty() {
        Some(allow_ip(&cfg, err)?)
    } else {
        None // a command message carries no allow IP
    };
    let encryption_key = cfg.encryption_key()?;
    let hmac_key = cfg.hmac_key_bytes()?;
    let digest_type: DigestType = cfg
        .digest_type
        .parse()
        .map_err(|_| anyhow!("unknown digest type: {}", cfg.digest_type))?;
    let encryption_mode: EncryptionMode = cfg.encryption_mode.parse().map_err(|_| {
        anyhow!(
            "unknown encryption mode: {} (use cbc or legacy)",
            cfg.encryption_mode
        )
    })?;
    let hmac_type = if cfg.use_hmac {
        cfg.hmac_digest_type
            .parse::<HmacType>()
            .map_err(|_| anyhow!("unknown HMAC type: {}", cfg.hmac_digest_type))?
    } else {
        HmacType::default()
    };
    let keys = KeySet::new(
        encryption_key,
        encryption_mode,
        hmac_key.map(|k| HmacKey::new(k.as_slice(), hmac_type)),
    );
    let request = build_request(&cfg, allow_ip.as_deref())?;

    let mut msg = SpaMessage::new(request).context("creating SPA message")?;
    msg.digest_type = digest_type;
    if !cfg.spoof_user.is_empty() {
        msg.username = cfg.spoof_user.clone();
    }
    if let Some(offset_ns) = time_offset(&cfg)? {
        msg.timestamp = timestamp_with_offset(offset_ns);
    }

    if cfg.verbose > 0 {
        print_spa_details(err, &msg, keys.encryption_mode, hmac_type)?;
    }

    let spa_data = msg.encrypt(&keys).context("encrypting SPA data")?;

    if cfg.verbose > 0 {
        writeln!(err, "SPA data length: {} bytes", spa_data.len())?;
    }
    if cfg.verbose > 1 {
        writeln!(err, "SPA data: {spa_data}")?;
    }

    if cfg.test {
        writeln!(out, "{spa_data}")?;
        return Ok(());
    }

    if cfg.verbose > 0 {
        writeln!(
            err,
            "Sending SPA packet to {}:{} (UDP)...",
            cfg.destination, cfg.server_port
        )?;
    }
    send(&cfg, &spa_data)?;
    if cfg.verbose > 0 {
        writeln!(err, "SPA packet sent successfully.")?;
    }
    Ok(())
}

/// The request: a server command, or an access message for the allow IP,
/// optionally with NAT access and a client timeout.
fn build_request(cfg: &ClientConfig, allow_ip: Option<&str>) -> Result<Request> {
    let Some(allow_ip) = allow_ip else {
        if !cfg.nat_access.is_empty() {
            bail!("NAT access (-N) cannot be combined with a server command (-C)");
        }
        return Ok(Request::Command(cfg.server_cmd.clone()));
    };
    let access: AccessMessage = format!("{allow_ip},{}", cfg.access)
        .parse()
        .context("encrypting SPA data")?;
    let client_timeout = if cfg.fw_timeout > 0 {
        let secs = u32::try_from(cfg.fw_timeout)
            .map_err(|_| anyhow!("fw_timeout {} is too large", cfg.fw_timeout))?;
        NonZeroU32::new(secs)
    } else {
        None
    };

    Ok(if cfg.nat_access.is_empty() {
        Request::Access {
            access,
            client_timeout,
        }
    } else if cfg.nat_local {
        Request::LocalNatAccess {
            access,
            nat_access: cfg.nat_access.clone(),
            client_timeout,
        }
    } else {
        Request::NatAccess {
            access,
            nat_access: cfg.nat_access.clone(),
            client_timeout,
        }
    })
}

/// `-a`, or `0.0.0.0` with `-s`, or the external IP looked up with `-R`.
fn allow_ip(cfg: &ClientConfig, err: &mut dyn Write) -> Result<String> {
    let mut ip = cfg.allow_ip.clone();
    if cfg.source_ip {
        ip = "0.0.0.0".into();
    }
    if cfg.resolve_ip && ip.is_empty() {
        let url = if cfg.resolve_url.is_empty() {
            resolve::DEFAULT_RESOLVE_URL
        } else {
            &cfg.resolve_url
        };
        if cfg.verbose > 0 {
            writeln!(err, "Resolving external IP via {url}...")?;
        }
        ip = resolve::resolve_external_ip(url)?;
        if cfg.verbose > 0 {
            writeln!(err, "Resolved external IP: {ip}")?;
        }
    }
    if ip.is_empty() {
        bail!("no source IP specified (use -a, -s, or -R)");
    }
    Ok(ip)
}

/// `--time-offset-plus` wins over `--time-offset-minus`. Nanoseconds.
fn time_offset(cfg: &ClientConfig) -> Result<Option<i128>> {
    if !cfg.time_offset_plus.is_empty() {
        return duration::parse_time_offset(&cfg.time_offset_plus)
            .map(Some)
            .map_err(|e| anyhow!(e));
    }
    if !cfg.time_offset_minus.is_empty() {
        return duration::parse_time_offset(&cfg.time_offset_minus)
            .map(|d| Some(-d))
            .map_err(|e| anyhow!(e));
    }
    Ok(None)
}

/// Now plus `offset_ns`, in whole Unix seconds (rounded down like Go's
/// `Time.Unix`).
fn timestamp_with_offset(offset_ns: i128) -> i64 {
    let now_ns = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    };
    let secs = (now_ns + offset_ns).div_euclid(1_000_000_000);
    i64::try_from(secs).unwrap_or(if secs < 0 { i64::MIN } else { i64::MAX })
}

fn send(cfg: &ClientConfig, spa_data: &fkospa::SpaData) -> Result<()> {
    let port = u16::try_from(cfg.server_port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| {
            anyhow!(
                "connecting to {}: invalid port {}",
                join_host_port(&cfg.destination, cfg.server_port),
                cfg.server_port
            )
        })?;
    let addr = join_host_port(&cfg.destination, cfg.server_port);
    fwknop::send_spa_data(&cfg.destination, port, spa_data).map_err(|e| match e {
        fwknop::Error::Send(io) => anyhow!("sending SPA packet to {addr}: {io}"),
        fwknop::Error::Dial { source, .. } => anyhow!("connecting to {addr}: {source}"),
        other => anyhow!("connecting to {addr}: {other}"),
    })
}

fn join_host_port(host: &str, port: i64) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn print_spa_details(
    err: &mut dyn Write,
    m: &SpaMessage,
    mode: EncryptionMode,
    hmac: HmacType,
) -> Result<()> {
    writeln!(err, "SPA message details:")?;
    writeln!(err, "  Random value: {}", m.rand_val)?;
    writeln!(err, "  Username:     {}", m.username)?;
    writeln!(
        err,
        "  Timestamp:    {} ({})",
        cli_common::time::rfc3339_local(m.timestamp),
        m.timestamp
    )?;
    writeln!(err, "  Message type: {}", m.message_type())?;
    writeln!(err, "  Access:       {}", m.request.message_text())?;
    if let Some(nat) = m.request.nat_access() {
        writeln!(err, "  NAT access:   {nat}")?;
    }
    if let Some(auth) = &m.server_auth {
        writeln!(err, "  Server auth:  {auth}")?;
    }
    if let Some(t) = m.request.client_timeout() {
        writeln!(err, "  Timeout:      {t}s")?;
    }
    writeln!(err, "  Digest:       {}", m.digest_type)?;
    writeln!(err, "  Encryption:   {mode}")?;
    writeln!(err, "  HMAC:         {hmac}")?;
    Ok(())
}

#[cfg(test)]
mod tests;
