//! fwknopd's configuration, merged like fwknop-go merges it (lowest priority
//! first): built-in defaults, `server.yaml`, `FWKNOPD_*` environment
//! variables, and the flags given on the command line.

use std::path::Path;

use anyhow::{Result, anyhow};

use cli_common::layers::{Layers, Raw, parse_untyped_yaml};

use crate::actions::ActionsConfig;
use crate::cli::Cli;

pub const DEFAULT_CONFIG_FILE: &str = "/etc/fwknop/server.yaml";
pub const DEFAULT_ACCESS_FILE: &str = "/etc/fwknop/access.yaml";
pub const DEFAULT_PID_FILE: &str = "/var/run/fwknop/fwknopd.pid";
pub const DEFAULT_LOG_FILE: &str = "/var/log/fwknop/fwknopd.log";
pub const DEFAULT_UDP_PORT: i64 = 62201;
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0";
pub const DEFAULT_MAX_AGE: i64 = 120;
pub const DEFAULT_ACTION_DIR: &str = "/etc/fwknop/actions";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerConfig {
    // Network
    pub udp_port: i64,
    pub bind_address: String,
    // Logging
    pub log_file: String,
    pub syslog_identity: String,
    pub syslog_facility: String,
    pub verbose: bool,
    // Daemon
    pub pid_file: String,
    // SPA processing
    pub max_spa_packet_age: i64,
    /// Accepted only so it can be warned about: fwknop-convert carries it
    /// over from C fwknopd configs, but the replay cache is in memory only.
    pub enable_digest_persistence: bool,
    // Actions
    pub actions: ActionsConfig,
    pub action_template: String,
    pub action_dir: String,
    // Files
    pub config_file: String,
    pub access_file: String,
    // Modes (command line)
    pub foreground: bool,
    pub test: bool,
    pub dump_config: bool,
    pub kill: bool,
    pub restart: bool,
    pub status: bool,
    pub show_version: bool,
}

/// Merges defaults, the config file, the environment and the flags.
pub fn load_server_config<I, K, V>(cli: &Cli, env: I) -> Result<ServerConfig>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let mut layers = Layers::new();
    for (key, value) in [
        ("udp_port", Raw::Int(DEFAULT_UDP_PORT)),
        ("bind_address", Raw::Str(DEFAULT_BIND_ADDRESS.into())),
        ("log_file", Raw::Str(DEFAULT_LOG_FILE.into())),
        ("syslog_identity", Raw::Str("fwknopd".into())),
        ("syslog_facility", Raw::Str("daemon".into())),
        ("pid_file", Raw::Str(DEFAULT_PID_FILE.into())),
        ("max_spa_packet_age", Raw::Int(DEFAULT_MAX_AGE)),
        ("action_dir", Raw::Str(DEFAULT_ACTION_DIR.into())),
        ("config_file", Raw::Str(DEFAULT_CONFIG_FILE.into())),
        ("access_file", Raw::Str(DEFAULT_ACCESS_FILE.into())),
    ] {
        layers.set(key, value);
    }

    // The config file to read comes from the flag alone.
    let config_file = cli
        .config_file
        .clone()
        .unwrap_or_else(|| DEFAULT_CONFIG_FILE.to_string());
    if Path::new(&config_file).exists() {
        let text = std::fs::read_to_string(&config_file)
            .map_err(|e| anyhow!("loading config file {config_file}: {e}"))?;
        match parse_untyped_yaml(&text)
            .map_err(|e| anyhow!("loading config file {config_file}: {e}"))?
        {
            Raw::Map(entries) => layers.load_map(entries),
            Raw::Null => {}
            _ => {
                return Err(anyhow!(
                    "loading config file {config_file}: expected a mapping"
                ));
            }
        }
    }

    layers.load_env_from("FWKNOPD_", env);
    apply_flags(&mut layers, cli);

    from_layers(&layers).map_err(|e| anyhow!("unmarshalling config: {e}"))
}

fn apply_flags(layers: &mut Layers, cli: &Cli) {
    for (key, value) in [
        ("config_file", &cli.config_file),
        ("access_file", &cli.access_file),
        ("pid_file", &cli.pid_file),
    ] {
        if let Some(v) = value {
            layers.set(key, Raw::Str(v.clone()));
        }
    }
    for (key, value) in [
        ("dump_config", cli.dump_config),
        ("foreground", cli.foreground),
        ("kill", cli.kill),
        ("restart", cli.restart),
        ("status", cli.status),
        ("test", cli.test),
        ("verbose", cli.verbose),
        ("version", cli.version),
    ] {
        match value {
            Some(v) => layers.set(key, Raw::Bool(v)),
            None => layers.set_default(key, Raw::Bool(false)),
        }
    }
}

fn from_layers(l: &Layers) -> Result<ServerConfig, String> {
    if let Some(v) = l.get("actions")
        && *v != Raw::Null
    {
        return Err(format!("'actions' expected a mapping, got {v:?}"));
    }
    Ok(ServerConfig {
        udp_port: l.int("udp_port")?,
        bind_address: l.string("bind_address")?,
        log_file: l.string("log_file")?,
        syslog_identity: l.string("syslog_identity")?,
        syslog_facility: l.string("syslog_facility")?,
        verbose: l.bool("verbose")?,
        pid_file: l.string("pid_file")?,
        max_spa_packet_age: l.int("max_spa_packet_age")?,
        enable_digest_persistence: l.bool("enable_digest_persistence")?,
        actions: ActionsConfig {
            validate: l.string("actions.validate")?,
            init: l.string("actions.init")?,
            check: l.string("actions.check")?,
            open: l.string("actions.open")?,
            close: l.string("actions.close")?,
            shutdown: l.string("actions.shutdown")?,
        },
        action_template: l.string("action_template")?,
        action_dir: l.string("action_dir")?,
        config_file: l.string("config_file")?,
        access_file: l.string("access_file")?,
        foreground: l.bool("foreground")?,
        test: l.bool("test")?,
        dump_config: l.bool("dump_config")?,
        kill: l.bool("kill")?,
        restart: l.bool("restart")?,
        status: l.bool("status")?,
        show_version: l.bool("version")?,
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("fwknopd").chain(args.iter().copied())).unwrap()
    }

    fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn defaults_without_a_config_file() {
        let cfg =
            load_server_config(&cli(&["-c", "/nonexistent/server.yaml"]), [("", ""); 0]).unwrap();
        assert_eq!(cfg.udp_port, 62201);
        assert_eq!(cfg.bind_address, "0.0.0.0");
        assert_eq!(cfg.log_file, DEFAULT_LOG_FILE);
        assert_eq!(cfg.syslog_identity, "fwknopd");
        assert_eq!(cfg.syslog_facility, "daemon");
        assert_eq!(cfg.pid_file, DEFAULT_PID_FILE);
        assert_eq!(cfg.max_spa_packet_age, 120);
        assert_eq!(cfg.action_dir, DEFAULT_ACTION_DIR);
        assert_eq!(cfg.access_file, DEFAULT_ACCESS_FILE);
        assert_eq!(cfg.config_file, "/nonexistent/server.yaml");
        assert!(!cfg.verbose && !cfg.test && !cfg.foreground);
    }

    #[test]
    fn file_then_env_then_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "server.yaml",
            "udp_port: 1000\nbind_address: 127.0.0.1\nverbose: true\nrun_dir: /tmp\n\
             actions:\n  open: \"echo open {{.SourceIP}}\"\n  close: echo close\n",
        );
        let cfg = load_server_config(&cli(&["-c", &path]), [("", ""); 0]).unwrap();
        assert_eq!(cfg.udp_port, 1000);
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert!(
            cfg.verbose,
            "an unchanged -v flag does not override the file"
        );
        assert_eq!(cfg.actions.open, "echo open {{.SourceIP}}");
        assert_eq!(cfg.actions.close, "echo close");

        let env = [
            ("FWKNOPD_UDP_PORT", "2000"),
            ("FWKNOPD_ACTIONS.CLOSE", "true"),
        ];
        let cfg = load_server_config(&cli(&["-c", &path]), env).unwrap();
        assert_eq!(cfg.udp_port, 2000);
        assert_eq!(cfg.actions.close, "true");

        let cfg = load_server_config(
            &cli(&[
                "-c",
                &path,
                "-v=false",
                "-a",
                "/x/access.yaml",
                "-p",
                "/x/pid",
                "-f",
                "-t",
            ]),
            env,
        )
        .unwrap();
        assert!(!cfg.verbose);
        assert_eq!(cfg.access_file, "/x/access.yaml");
        assert_eq!(cfg.pid_file, "/x/pid");
        assert!(cfg.foreground && cfg.test);
    }

    #[test]
    fn config_file_may_set_access_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "server.yaml", "access_file: /from/file.yaml\n");
        let cfg = load_server_config(&cli(&["-c", &path]), [("", ""); 0]).unwrap();
        assert_eq!(cfg.access_file, "/from/file.yaml");
    }

    #[test]
    fn bad_config_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "server.yaml", "udp_port: [1, 2\n");
        let err = load_server_config(&cli(&["-c", &path]), [("", ""); 0]).unwrap_err();
        assert!(err.to_string().starts_with("loading config file"), "{err}");

        let path = write(&dir, "server2.yaml", "udp_port: abc\n");
        let err = load_server_config(&cli(&["-c", &path]), [("", ""); 0]).unwrap_err();
        assert!(err.to_string().contains("udp_port"), "{err}");
    }

    #[test]
    fn sample_configs_load() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for rel in [
            "conf_files/server.yaml",
            "examples/configs/server-iptables.yaml",
            "examples/configs/server-nftables.yaml",
        ] {
            let path = root.join(rel);
            if !path.exists() {
                continue; // copied in with the packaging milestone
            }
            load_server_config(&cli(&["-c", path.to_str().unwrap()]), [("", ""); 0])
                .unwrap_or_else(|e| panic!("{rel}: {e:#}"));
        }
    }
}
